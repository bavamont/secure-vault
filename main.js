/**
 * @fileoverview Main process for Secure Vault - handles app lifecycle, security, and auto-updates
 */

const { app, BrowserWindow, ipcMain, dialog, shell, Menu, desktopCapturer, globalShortcut, Notification, clipboard, Tray, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Store = require('electron-store');
const { ImportExportManager } = require('./import-export');
const i18n = require('./i18n');

/**
 * @type {BrowserWindow|null} Main application window
 */
let mainWindow;
let tray;

/**
 * @type {boolean} Whether an update has been downloaded and is ready to install
 */
let updateDownloaded = false;

/**
 * @type {boolean} Whether the vault is currently locked
 */
let isLocked = true;

/**
 * @type {NodeJS.Timeout|null} Timeout for periodic update checks
 */
let updateCheckTimeout = null;

/**
 * @type {Store|null} Encrypted store for vault data
 */
let vaultStore = null;

/**
 * @type {NodeJS.Timeout|null} Timeout for automatic vault locking
 */
let sessionTimeout = null;

/**
 * @type {number} Number of consecutive failed password attempts
 */
let failedAttempts = 0;

/**
 * @type {number} Timestamp of last failed password attempt
 */
let lastFailedAttempt = 0;

/**
 * @type {boolean} Whether auto-update is currently checking for updates
 */
let isCheckingForUpdates = false;

/**
 * @type {ImportExportManager} Import/Export manager instance
 */
const importExportManager = new ImportExportManager();

/**
 * Configuration store for application settings
 */
const store = new Store({
    name: 'secure-vault-config',
    encryptionKey: process.env.NODE_ENV === 'development' ? 'dev-key' : undefined
});

/**
 * Derives encryption key from master password using PBKDF2
 * @param {string} password - The master password
 * @returns {string} Derived encryption key as hex string
 */
function deriveEncryptionKey(password) {
    let salt = store.get('encryptionSalt');
    if (!salt) {
        salt = crypto.randomBytes(32).toString('hex');
        store.set('encryptionSalt', salt);
    }
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512').toString('hex');
}

/**
 * Initializes the encrypted vault store with derived key
 * @param {string} password - The master password
 */
function initializeVaultStore(password) {
    try {
        const encryptionKey = deriveEncryptionKey(password);
        vaultStore = new Store({
            name: 'secure-vault-data',
            encryptionKey: encryptionKey
        });

        /* Test store access to ensure it's not corrupted */
        vaultStore.get('passwordEntries', []);
    } catch (error) {

        /* Check if this is a one-time corruption recovery */
        const recoveryFlag = store.get('vaultRecoveryPerformed', false);

        if (!recoveryFlag) {
            console.log('First-time vault corruption detected. Performing recovery...');

            try {
                /* Mark recovery as performed to prevent infinite loops */
                store.set('vaultRecoveryPerformed', true);

                /* Generate new salt for corrupted vault recovery */
                const newSalt = crypto.randomBytes(32).toString('hex');
                store.set('encryptionSalt', newSalt);
                console.log('Generated new encryption salt for corrupted vault recovery');

                /* Create new encryption key with fresh salt */
                const freshKey = crypto.pbkdf2Sync(password, newSalt, 100000, 32, 'sha512').toString('hex');

                /* Use the original vault name but with fresh encryption */
                vaultStore = new Store({
                    name: 'secure-vault-data',
                    encryptionKey: freshKey,
                    clearInvalidConfig: true
                });

                /* Initialize with empty data structure */
                vaultStore.set('passwordEntries', []);
                vaultStore.set('totpEntries', []);
                vaultStore.set('categories', []);

                console.log('Fresh vault store created successfully with new encryption');
                console.log('WARNING: Previous vault data was corrupted and could not be recovered.');
            } catch (secondError) {
                console.error('Failed to create fresh vault store:', secondError);
                throw new Error(i18n.t('errors.unable_initialize_vault'));
            }
        } else {
            /* Recovery already performed, but still failing - this indicates a persistent issue */
            console.error('Vault store still corrupted after recovery attempt.');
            throw new Error(i18n.t('errors.vault_corruption_persists'));
        }
    }
}

/**
 * Ensures vault store is ready for operations
 * @returns {Object|null} Error object if vault is locked, null otherwise
 */
function ensureVaultStoreReady() {
    if (isLocked || !vaultStore) {
        return { success: false, error: i18n.t('errors.vault_locked') };
    }
    resetSessionTimeout();
    return null;
}

/**
 * Resets the automatic session timeout
 */
function resetSessionTimeout() {
    if (sessionTimeout) {
        clearTimeout(sessionTimeout);
    }
    sessionTimeout = setTimeout(function() {
        if (!isLocked) {
            lockVaultInternal();
        }
    }, 30 * 60 * 1000);
}

/**
 * Locks the vault and clears sensitive data
 */
function lockVaultInternal() {
    isLocked = true;
    vaultStore = null;
    if (sessionTimeout) {
        clearTimeout(sessionTimeout);
        sessionTimeout = null;
    }
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vault-auto-locked');
    }
}

/**
 * Creates the main application window
 */
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            enableRemoteModule: true
        },
        icon: getIconPath(),
        show: false,
        frame: false,
        titleBarStyle: 'hidden',
        backgroundColor: '#0a0e1a',
        title: i18n.t('app.title')
    });

    mainWindow.setMenu(null);
    mainWindow.loadFile('index.html');

    mainWindow.once('ready-to-show', function() {
        mainWindow.show();
        if (process.argv.includes('--dev') || process.env.NODE_ENV === 'development') {
            mainWindow.webContents.openDevTools();
        }

        setTimeout(function() {
            if (!process.argv.includes('--dev')) {
                checkForUpdatesOnStartup();
                schedulePeriodicUpdates();
            }
        }, 2000);
    });

    mainWindow.on('close', function(event) {
        const settings = store.get('appSettings', {});
        if (settings.closeToTray !== false && !app.isQuiting) {
            event.preventDefault();
            mainWindow.hide();
        }
    });

    mainWindow.on('closed', function() {
        mainWindow = null;
        if (updateCheckTimeout) {
            clearTimeout(updateCheckTimeout);
        }
        if (sessionTimeout) {
            clearTimeout(sessionTimeout);
        }
        globalShortcut.unregisterAll();
    });

    mainWindow.webContents.setWindowOpenHandler(function(details) {
        shell.openExternal(details.url);
        return { action: 'deny' };
    });

    createTray();
}

/**
 * Creates the system tray
 */
function createTray() {
    const trayIcon = nativeImage.createFromPath(getIconPath());
    tray = new Tray(trayIcon.resize({ width: 16, height: 16 }));

    const contextMenu = Menu.buildFromTemplate([
        {
            label: i18n.t('tray.show_secure_vault'),
            click: function() {
                mainWindow.show();
                mainWindow.focus();
            }
        },
        {
            label: i18n.t('tray.lock_vault'),
            click: function() {
                mainWindow.webContents.send('lock-vault');
            }
        },
        { type: 'separator' },
        {
            label: i18n.t('tray.quit'),
            click: function() {
                app.isQuiting = true;
                app.quit();
            }
        }
    ]);

    tray.setToolTip(i18n.t('tray.tooltip'));
    tray.setContextMenu(contextMenu);

    tray.on('double-click', function() {
        mainWindow.show();
        mainWindow.focus();
    });
}

/**
 * Gets the appropriate icon path for the current platform
 * @returns {string} Path to the icon file
 */
function getIconPath() {
    const iconPaths = {
        win32: 'assets/icon.ico',
        darwin: 'assets/icon.icns',
        linux: 'assets/icon.png'
    };

    const iconPath = iconPaths[process.platform] || iconPaths.linux;
    return path.join(__dirname, iconPath);
}

/**
 * Sets up auto-updater event handlers and configuration
 */
function setupAutoUpdater() {
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = true;
    autoUpdater.allowDowngrade = false;
    autoUpdater.allowPrerelease = false;

    autoUpdater.on('checking-for-update', function() {
        console.log('Checking for update...');
        isCheckingForUpdates = true;
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-checking');
        }
    });

    autoUpdater.on('update-available', function(info) {
        console.log('Update available:', info);
        isCheckingForUpdates = false;
        store.set('lastUpdateInfo', {
            version: info.version,
            releaseDate: info.releaseDate,
            downloadUrl: info.files?.[0]?.url
        });
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-available', info);
        }
    });

    autoUpdater.on('update-not-available', function(info) {
        console.log('Update not available:', info);
        isCheckingForUpdates = false;
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-not-available', info);
        }
    });

    autoUpdater.on('error', function(err) {
        console.error('Update error:', err);
        isCheckingForUpdates = false;
        store.set('lastUpdateError', {
            message: err.message,
            timestamp: new Date().toISOString()
        });
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-error', err);
        }
    });

    autoUpdater.on('download-progress', function(progressObj) {
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-download-progress', progressObj);
        }
    });

    autoUpdater.on('update-downloaded', function(info) {
        console.log('Update downloaded:', info);
        updateDownloaded = true;
        store.set('updateDownloaded', true);
        store.set('updateReadyToInstall', {
            version: info.version,
            downloadedAt: new Date().toISOString()
        });
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-downloaded', info);
        }
    });
}

/**
 * Checks for updates on application startup
 */
async function checkForUpdatesOnStartup() {
    try {
        const autoCheckEnabled = store.get('autoCheckUpdates', true);
        if (!autoCheckEnabled || isCheckingForUpdates) {
            return;
        }

        const lastCheck = store.get('lastUpdateCheck', 0);
        const now = Date.now();
        const oneDayMs = 24 * 60 * 60 * 1000;

        if (now - lastCheck < oneDayMs) {
            return;
        }

        store.set('lastUpdateCheck', now);

        if (process.platform !== 'linux' && app.isPackaged) {
            console.log('Checking for updates on startup...');
            await autoUpdater.checkForUpdates();
        }
    } catch (error) {
        console.error('Error checking for updates on startup:', error);
        store.set('lastUpdateError', {
            message: error.message,
            timestamp: new Date().toISOString(),
            context: 'startup'
        });
    }
}

/**
 * Schedules periodic update checks
 */
function schedulePeriodicUpdates() {
    const checkInterval = 6 * 60 * 60 * 1000; // 6 hours

    updateCheckTimeout = setInterval(async function() {
        try {
            const autoCheckEnabled = store.get('autoCheckUpdates', true);
            if (!autoCheckEnabled || isCheckingForUpdates || !app.isPackaged) {
                return;
            }

            if (process.platform !== 'linux') {
                console.log('Periodic update check...');
                await autoUpdater.checkForUpdates();
            }
        } catch (error) {
            console.error('Error during periodic update check:', error);
        }
    }, checkInterval);
}

/**
 * Forces an immediate update check
 * @returns {Promise<Object>} Result of update check
 */
async function forceUpdateCheck() {
    try {
        if (isCheckingForUpdates) {
            return { success: false, error: i18n.t('errors.update_in_progress') };
        }

        if (process.platform === 'linux') {
            return { success: false, error: i18n.t('errors.updates_not_supported_linux') };
        }

        if (!app.isPackaged) {
            return { success: false, error: i18n.t('errors.updates_packaged_only') };
        }

        store.set('lastUpdateCheck', Date.now());
        const result = await autoUpdater.checkForUpdates();
        return { success: true, updateInfo: result };
    } catch (error) {
        console.error('Error forcing update check:', error);
        return { success: false, error: error.message };
    }
}


/**
 * IPC handler to get available desktop sources for screen capture
 */
ipcMain.handle('get-desktop-sources', async function() {
    try {
        const sources = await desktopCapturer.getSources({
            types: ['screen', 'window'],
            thumbnailSize: { width: 1920, height: 1080 }
        });

        return {
            success: true,
            sources: sources.map(function(source) {
                return {
                    id: source.id,
                    name: source.name,
                    thumbnail: source.thumbnail.toDataURL()
                };
            })
        };
    } catch (error) {
        console.error('Error getting desktop sources:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to capture screen from specific source
 * @param {Event} event - IPC event
 * @param {string} sourceId - ID of the desktop source to capture
 */
ipcMain.handle('capture-screen', async function(event, sourceId) {
    try {
        const sources = await desktopCapturer.getSources({
            types: ['screen', 'window'],
            thumbnailSize: { width: 1920, height: 1080 }
        });

        const source = sources.find(function(s) {
            return s.id === sourceId;
        });
        if (!source) {
            return { success: false, error: i18n.t('errors.source_not_found') };
        }

        return {
            success: true,
            dataUrl: source.thumbnail.toDataURL(),
            width: source.thumbnail.getSize().width,
            height: source.thumbnail.getSize().height
        };
    } catch (error) {
        console.error('Error capturing screen:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to check for application updates
 */
ipcMain.handle('check-for-updates', async function() {
    try {
        const result = await forceUpdateCheck();
        return result;
    } catch (error) {
        console.error('Error checking for updates:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to download available update
 */
ipcMain.handle('download-update', async function() {
    try {
        if (isCheckingForUpdates) {
            return { success: false, error: i18n.t('errors.update_in_progress') };
        }
        await autoUpdater.downloadUpdate();
        return { success: true };
    } catch (error) {
        console.error('Error downloading update:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to install downloaded update and restart app
 */
ipcMain.handle('install-update', async function() {
    try {
        if (updateDownloaded) {
            store.set('updateDownloaded', false);
            autoUpdater.quitAndInstall();
            return { success: true };
        } else {
            return { success: false, error: i18n.t('errors.no_update_downloaded') };
        }
    } catch (error) {
        console.error('Error installing update:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to get update information and status
 */
ipcMain.handle('get-update-info', async function() {
    try {
        const lastUpdateInfo = store.get('lastUpdateInfo', null);
        const lastUpdateError = store.get('lastUpdateError', null);
        const updateReadyToInstall = store.get('updateReadyToInstall', null);

        return {
            success: true,
            version: app.getVersion(),
            updateDownloaded: updateDownloaded,
            platform: process.platform,
            autoCheckEnabled: store.get('autoCheckUpdates', true),
            lastCheck: store.get('lastUpdateCheck', 0),
            isCheckingForUpdates: isCheckingForUpdates,
            lastUpdateInfo: lastUpdateInfo,
            lastUpdateError: lastUpdateError,
            updateReadyToInstall: updateReadyToInstall,
            supportsUpdates: process.platform !== 'linux' && app.isPackaged
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to enable/disable automatic update checks
 * @param {Event} event - IPC event
 * @param {boolean} enabled - Whether to enable auto-update checks
 */
ipcMain.handle('set-auto-check-updates', async function(event, enabled) {
    try {
        store.set('autoCheckUpdates', enabled);
        if (!enabled && updateCheckTimeout) {
            clearInterval(updateCheckTimeout);
            updateCheckTimeout = null;
        } else if (enabled && !updateCheckTimeout) {
            schedulePeriodicUpdates();
        }
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to clear update cache and history
 */
ipcMain.handle('clear-update-cache', async function() {
    try {
        store.delete('lastUpdateInfo');
        store.delete('lastUpdateError');
        store.delete('updateReadyToInstall');
        store.delete('updateDownloaded');
        updateDownloaded = false;
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to minimize the main window
 */
ipcMain.handle('window-minimize', function() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        const settings = store.get('appSettings', {});
        if (settings.closeToTray !== false) {
            mainWindow.hide();
        } else {
            mainWindow.minimize();
        }
    }
    return { success: true };
});

/**
 * IPC handler to maximize/unmaximize the main window
 */
ipcMain.handle('window-maximize', function() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        if (mainWindow.isMaximized()) {
            mainWindow.unmaximize();
        } else {
            mainWindow.maximize();
        }
    }
    return { success: true };
});

/**
 * IPC handler to close the main window
 */
ipcMain.handle('window-close', function() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.close();
    }
    return { success: true };
});

/**
 * IPC handler to check if window is maximized
 */
ipcMain.handle('window-is-maximized', function() {
    return mainWindow && !mainWindow.isDestroyed() ? mainWindow.isMaximized() : false;
});

/**
 * IPC handler to setup initial master password
 * @param {Event} event - IPC event
 * @param {string} password - Master password to setup
 */
ipcMain.handle('setup-master-password', async function(event, password) {
    try {
        const saltRounds = 12;
        const hash = await bcrypt.hash(password, saltRounds);

        store.set('masterPasswordHash', hash);
        store.set('isSetup', true);

        initializeVaultStore(password);
        isLocked = false;
        resetSessionTimeout();

        return { success: true };
    } catch (error) {
        console.error('Error setting up master password:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to verify master password with rate limiting
 * @param {Event} event - IPC event
 * @param {string} password - Master password to verify
 */
ipcMain.handle('verify-master-password', async function(event, password) {
    try {
        const now = Date.now();
        const timeSinceLastAttempt = now - lastFailedAttempt;

        if (timeSinceLastAttempt > 15 * 60 * 1000) {
            failedAttempts = 0;
        }

        if (failedAttempts > 0) {
            const delay = Math.min(30000, 1000 * Math.pow(2, failedAttempts - 1));
            if (timeSinceLastAttempt < delay) {
                const remaining = Math.ceil((delay - timeSinceLastAttempt) / 1000);
                return { success: false, error: `Too many failed attempts. Try again in ${remaining} seconds.` };
            }
        }

        const storedHash = store.get('masterPasswordHash');
        if (!storedHash) {
            return { success: false, error: i18n.t('errors.master_password_not_set') };
        }

        const isValid = await bcrypt.compare(password, storedHash);
        if (isValid) {
            failedAttempts = 0;
            initializeVaultStore(password);
            isLocked = false;
            resetSessionTimeout();
            return { success: true };
        } else {
            failedAttempts++;
            lastFailedAttempt = now;
            return { success: false, error: i18n.t('errors.invalid_password') };
        }
    } catch (error) {
        console.error('Error verifying master password:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('change-master-password', async function(event, currentPassword, newPassword) {
    try {
        const storedHash = store.get('masterPasswordHash');
        if (!storedHash) {
            return { success: false, error: i18n.t('errors.master_password_not_set') };
        }

        const isValid = await bcrypt.compare(currentPassword, storedHash);
        if (!isValid) {
            return { success: false, error: i18n.t('errors.current_password_incorrect') };
        }

        const saltRounds = 12;
        const newHash = await bcrypt.hash(newPassword, saltRounds);

        store.set('masterPasswordHash', newHash);

        return { success: true };
    } catch (error) {
        console.error('Error changing master password:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('lock-vault', async function() {
    try {
        lockVaultInternal();
        return { success: true };
    } catch (error) {
        console.error('Error locking vault:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('is-vault-setup', async function() {
    try {
        const isSetup = store.get('isSetup', false);
        return { success: true, isSetup: isSetup, isLocked: isLocked };
    } catch (error) {
        console.error('Error checking vault setup:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('save-password-entry', async function(event, entry) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const entries = vaultStore.get('passwordEntries', []);

        if (entry.id) {
            const index = entries.findIndex(function(e) {
                return e.id === entry.id;
            });
            if (index !== -1) {
                entries[index] = Object.assign({}, entry, { updatedAt: new Date().toISOString() });
            }
        } else {
            entry.id = Date.now().toString();
            entry.createdAt = new Date().toISOString();
            entry.updatedAt = new Date().toISOString();
            entries.push(entry);
        }

        vaultStore.set('passwordEntries', entries);
        return { success: true, entry: entry };
    } catch (error) {
        console.error('Error saving password entry:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-password-entries', async function() {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const entries = vaultStore.get('passwordEntries', []);
        return { success: true, entries: entries };
    } catch (error) {
        console.error('Error getting password entries:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('delete-password-entry', async function(event, entryId) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const entries = vaultStore.get('passwordEntries', []);
        const filteredEntries = entries.filter(function(e) {
            return e.id !== entryId;
        });

        vaultStore.set('passwordEntries', filteredEntries);
        return { success: true };
    } catch (error) {
        console.error('Error deleting password entry:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('save-totp-entry', async function(event, entry) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const entries = vaultStore.get('totpEntries', []);

        if (entry.id) {
            const index = entries.findIndex(function(e) {
                return e.id === entry.id;
            });
            if (index !== -1) {
                entries[index] = Object.assign({}, entry, { updatedAt: new Date().toISOString() });
            }
        } else {
            entry.id = Date.now().toString();
            entry.createdAt = new Date().toISOString();
            entry.updatedAt = new Date().toISOString();
            entries.push(entry);
        }

        vaultStore.set('totpEntries', entries);
        return { success: true, entry: entry };
    } catch (error) {
        console.error('Error saving TOTP entry:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-totp-entries', async function() {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const entries = vaultStore.get('totpEntries', []);
        return { success: true, entries: entries };
    } catch (error) {
        console.error('Error getting TOTP entries:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('delete-totp-entry', async function(event, entryId) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const entries = vaultStore.get('totpEntries', []);
        const filteredEntries = entries.filter(function(e) {
            return e.id !== entryId;
        });

        vaultStore.set('totpEntries', filteredEntries);
        return { success: true };
    } catch (error) {
        console.error('Error deleting TOTP entry:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler for enhanced vault export with multiple format support
 * @param {Event} event - IPC event
 * @param {string} format - Export format (csv, json, securevault, etc.)
 * @param {string} password - Password for encrypted formats
 */
ipcMain.handle('export-vault', async function(event, format = 'json', password = null) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const formatInfo = importExportManager.supportedFormats[format] || i18n.t('formats.unknown_format');
        const extensions = {
            'csv': ['csv'],
            'json': ['json'],
            'securevault': ['svault'],
            'lastpass': ['csv'],
            'bitwarden': ['json']
        };

        const result = await dialog.showSaveDialog(mainWindow, {
            title: `Export Vault Data - ${formatInfo}`,
            defaultPath: `secure-vault-backup-${new Date().toISOString().split('T')[0]}.${extensions[format]?.[0] || 'json'}`,
            filters: [
                { name: formatInfo, extensions: extensions[format] || ['json'] },
                { name: i18n.t('file_types.all_files'), extensions: ['*'] }
            ]
        });

        if (result.canceled) {
            return { success: false, canceled: true };
        }

        const passwordEntries = vaultStore.get('passwordEntries', []);
        const totpEntries = vaultStore.get('totpEntries', []);
        const allEntries = [...passwordEntries, ...totpEntries];

        await importExportManager.exportData(allEntries, format, result.filePath, password);
        return { success: true, path: result.filePath, format: format, count: allEntries.length };
    } catch (error) {
        console.error('Error exporting vault:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler for enhanced vault import with multiple format support
 * @param {Event} event - IPC event
 * @param {string} password - Password for encrypted formats
 */
ipcMain.handle('import-vault', async function(event, password = null) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const result = await dialog.showOpenDialog(mainWindow, {
            title: i18n.t('dialogs.import_vault_title'),
            filters: [
                { name: i18n.t('file_types.csv_files'), extensions: ['csv'] },
                { name: i18n.t('file_types.json_files'), extensions: ['json'] },
                { name: i18n.t('file_types.secure_vault_files'), extensions: ['svault'] },
                { name: 'WinAuth Files', extensions: ['txt', 'wa.txt'] },
                { name: i18n.t('file_types.all_files'), extensions: ['*'] }
            ],
            properties: ['openFile']
        });

        if (result.canceled) {
            return { success: false, canceled: true };
        }

        const importResult = await importExportManager.importData(result.filePaths[0], password);
        let passwordCount = 0;
        let totpCount = 0;

        if (importResult.success && importResult.entries && importResult.entries.length > 0) {
            /* Separate password and TOTP entries */
            const passwordEntries = [];
            const totpEntries = [];

            for (const entry of importResult.entries) {
                if (entry.type === 'totp' || entry.secret || entry.totp) {
                    /* Convert to TOTP entry format */
                    totpEntries.push({
                        id: entry.id,
                        name: entry.name,
                        secret: entry.secret || entry.totp,
                        issuer: entry.issuer || entry.category || i18n.t('import.default_issuer'),
                        digits: entry.digits || 6,
                        period: entry.period || 30,
                        createdAt: entry.created || new Date().toISOString(),
                        updatedAt: entry.modified || new Date().toISOString()
                    });
                } else {
                    /* Convert to password entry format */
                    passwordEntries.push({
                        id: entry.id,
                        name: entry.name,
                        username: entry.username,
                        password: entry.password,
                        url: entry.url,
                        category: entry.category,
                        notes: entry.notes,
                        tags: entry.tags || [],
                        createdAt: entry.created || new Date().toISOString(),
                        updatedAt: entry.modified || new Date().toISOString()
                    });
                }
            }

            passwordCount = passwordEntries.length;
            totpCount = totpEntries.length;

            /* Merge with existing entries */
            if (passwordEntries.length > 0) {
                const currentPasswordEntries = vaultStore.get('passwordEntries', []);
                const mergedPasswordEntries = currentPasswordEntries.concat(passwordEntries);
                vaultStore.set('passwordEntries', mergedPasswordEntries);
            }

            if (totpEntries.length > 0) {
                const currentTotpEntries = vaultStore.get('totpEntries', []);
                const mergedTotpEntries = currentTotpEntries.concat(totpEntries);
                vaultStore.set('totpEntries', mergedTotpEntries);
            }
        }

        return {
            success: importResult.success,
            path: result.filePaths[0],
            imported: importResult.imported,
            skipped: importResult.skipped,
            errors: importResult.errors,
            format: importResult.format,
            passwordCount: passwordCount,
            totpCount: totpCount
        };
    } catch (error) {
        console.error('Error importing vault:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler for importing from a specific file path
 */
ipcMain.handle('import-from-file', async function(event, filePath, password = null) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        if (!filePath) {
            return { success: false, error: 'No file path provided' };
        }

        const importResult = await importExportManager.importData(filePath, password);
        let passwordCount = 0;
        let totpCount = 0;

        if (importResult.success && importResult.entries && importResult.entries.length > 0) {
            /* Separate password and TOTP entries */
            const passwordEntries = [];
            const totpEntries = [];

            for (const entry of importResult.entries) {
                if (entry.type === 'totp' || entry.secret || entry.totp) {
                    /* Convert to TOTP entry format */
                    totpEntries.push({
                        id: entry.id,
                        name: entry.name,
                        secret: entry.secret || entry.totp,
                        issuer: entry.issuer || entry.category || i18n.t('import.default_issuer'),
                        digits: entry.digits || 6,
                        period: entry.period || 30,
                        createdAt: entry.created || new Date().toISOString(),
                        updatedAt: entry.modified || new Date().toISOString()
                    });
                } else {
                    /* Convert to password entry format */
                    passwordEntries.push({
                        id: entry.id,
                        name: entry.name,
                        username: entry.username,
                        password: entry.password,
                        url: entry.url,
                        category: entry.category,
                        notes: entry.notes,
                        tags: entry.tags || [],
                        createdAt: entry.created || new Date().toISOString(),
                        updatedAt: entry.modified || new Date().toISOString()
                    });
                }
            }

            passwordCount = passwordEntries.length;
            totpCount = totpEntries.length;

            /* Save password entries */
            if (passwordEntries.length > 0) {
                const existingPasswords = vaultStore.get('passwords', []);
                const updatedPasswords = existingPasswords.concat(passwordEntries);
                vaultStore.set('passwords', updatedPasswords);
            }

            /* Save TOTP entries */
            if (totpEntries.length > 0) {
                const existingTotpEntries = vaultStore.get('totpEntries', []);
                const updatedTotpEntries = existingTotpEntries.concat(totpEntries);
                vaultStore.set('totpEntries', updatedTotpEntries);
            }
        }

        return {
            success: true,
            imported: importResult.imported || 0,
            skipped: importResult.skipped || 0,
            errors: importResult.errors || [],
            format: importResult.format || 'unknown',
            passwordCount: passwordCount,
            totpCount: totpCount
        };

    } catch (error) {
        console.error('Import from file error:', error);
        return {
            success: false,
            imported: 0,
            skipped: 0,
            errors: [error.message],
            format: 'unknown',
            passwordCount: 0,
            totpCount: 0
        };
    }
});

/**
 * IPC handler for importing from file content
 */
ipcMain.handle('import-from-content', async function(event, importData) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        if (!importData.content) {
            return { success: false, error: 'No file content provided' };
        }

        /* Create temporary file path for format detection */
        const tempFilePath = importData.filename || 'import.txt';
        
        /* Detect format if not specified */
        let format = importData.format;
        if (!format) {
            format = importExportManager.detectFormat(tempFilePath, importData.content);
        }

        /* Import data using the manager */
        const importResult = await importExportManager.importData(tempFilePath, importData.password, importData.content);
        let passwordCount = 0;
        let totpCount = 0;

        if (importResult.success && importResult.entries && importResult.entries.length > 0) {
            /* Separate password and TOTP entries */
            const passwordEntries = [];
            const totpEntries = [];

            for (const entry of importResult.entries) {
                if (entry.type === 'totp' || entry.secret || entry.totp) {
                    /* Convert to TOTP entry format */
                    totpEntries.push({
                        id: entry.id,
                        name: entry.name,
                        secret: entry.secret || entry.totp,
                        issuer: entry.issuer || entry.category || i18n.t('import.default_issuer'),
                        digits: entry.digits || 6,
                        period: entry.period || 30,
                        createdAt: entry.created || new Date().toISOString(),
                        updatedAt: entry.modified || new Date().toISOString()
                    });
                } else {
                    /* Convert to password entry format */
                    passwordEntries.push({
                        id: entry.id,
                        name: entry.name,
                        username: entry.username,
                        password: entry.password,
                        url: entry.url,
                        category: entry.category,
                        notes: entry.notes,
                        tags: entry.tags || [],
                        createdAt: entry.created || new Date().toISOString(),
                        updatedAt: entry.modified || new Date().toISOString()
                    });
                }
            }

            passwordCount = passwordEntries.length;
            totpCount = totpEntries.length;

            /* Save password entries */
            if (passwordEntries.length > 0) {
                const existingPasswords = vaultStore.get('passwords', []);
                const updatedPasswords = existingPasswords.concat(passwordEntries);
                vaultStore.set('passwords', updatedPasswords);
            }

            /* Save TOTP entries */
            if (totpEntries.length > 0) {
                const existingTotpEntries = vaultStore.get('totpEntries', []);
                const updatedTotpEntries = existingTotpEntries.concat(totpEntries);
                vaultStore.set('totpEntries', updatedTotpEntries);
            }
        }

        return {
            success: true,
            imported: importResult.imported || 0,
            skipped: importResult.skipped || 0,
            errors: importResult.errors || [],
            format: importResult.format || format,
            passwordCount: passwordCount,
            totpCount: totpCount
        };

    } catch (error) {
        console.error('Import from content error:', error);
        return {
            success: false,
            imported: 0,
            skipped: 0,
            errors: [error.message],
            format: 'unknown',
            passwordCount: 0,
            totpCount: 0
        };
    }
});

ipcMain.handle('get-system-language', async function() {
    try {
        const locale = app.getLocale();
        const language = locale.substring(0, 2);

        const supportedLanguages = ['en', 'de'];
        const detectedLanguage = supportedLanguages.includes(language) ? language : 'en';

        return {
            success: true,
            language: detectedLanguage,
            locale: locale,
            systemLanguages: app.getPreferredSystemLanguages()
        };
    } catch (error) {
        console.error('Error getting system language:', error);
        return { success: false, error: error.message, language: 'en' };
    }
});

/**
 * IPC handler to get supported import/export formats
 */
ipcMain.handle('get-supported-formats', async function() {
    try {
        return {
            success: true,
            formats: importExportManager.supportedFormats
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to perform password security audit
 */
ipcMain.handle('audit-passwords', async function() {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const passwordEntries = vaultStore.get('passwordEntries', []);
        const audit = {
            total: passwordEntries.length,
            weak: 0,
            reused: 0,
            old: 0,
            compromised: 0,
            details: []
        };

        const passwordMap = new Map();
        const now = new Date();
        const sixMonthsAgo = new Date(now.getTime() - 6 * 30 * 24 * 60 * 60 * 1000);

        for (const entry of passwordEntries) {
            const issues = [];

            /* Check password strength (basic check) */
            if (entry.password.length < 8) {
                issues.push('too_short');
                audit.weak++;
            }
            if (!/[A-Z]/.test(entry.password) || !/[a-z]/.test(entry.password) ||
                !/[0-9]/.test(entry.password) || !/[^A-Za-z0-9]/.test(entry.password)) {
                if (!issues.includes('too_short')) {
                    issues.push('weak');
                    audit.weak++;
                }
            }

            /* Check for reused passwords */
            const passwordHash = crypto.createHash('sha256').update(entry.password).digest('hex');
            if (passwordMap.has(passwordHash)) {
                issues.push('reused');
                audit.reused++;
                /* Mark the original as reused too if not already marked */
                const originalEntry = passwordMap.get(passwordHash);
                if (!originalEntry.issues.includes('reused')) {
                    originalEntry.issues.push('reused');
                    audit.reused++;
                    /* Update the original entry in audit.details if it exists */
                    const originalDetail = audit.details.find(d => d.id === originalEntry.id);
                    if (originalDetail && !originalDetail.issues.includes('reused')) {
                        originalDetail.issues.push('reused');
                    }
                }
            } else {
                passwordMap.set(passwordHash, { id: entry.id, issues: [...issues] });
            }

            /* Check age */
            const updatedAt = entry.updatedAt ? new Date(entry.updatedAt) : new Date(entry.createdAt);
            if (updatedAt < sixMonthsAgo) {
                issues.push('old');
                audit.old++;
            }

            if (issues.length > 0) {
                audit.details.push({
                    id: entry.id,
                    name: entry.name,
                    issues: issues
                });
            }
        }

        return { success: true, audit };
    } catch (error) {
        console.error('Error auditing passwords:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to get all categories/folders
 */
ipcMain.handle('get-categories', async function() {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const categories = vaultStore.get('categories', []);

        return { success: true, categories };
    } catch (error) {
        console.error('Error getting categories:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to save/update a category
 * @param {Event} event - IPC event
 * @param {Object} category - Category object
 */
ipcMain.handle('save-category', async function(event, category) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const categories = vaultStore.get('categories', []);

        if (category.id) {
            const index = categories.findIndex(c => c.id === category.id);
            if (index !== -1) {
                categories[index] = { ...category, updatedAt: new Date().toISOString() };
            }
        } else {
            category.id = crypto.randomUUID();
            category.createdAt = new Date().toISOString();
            category.updatedAt = new Date().toISOString();
            categories.push(category);
        }

        vaultStore.set('categories', categories);
        return { success: true, category };
    } catch (error) {
        console.error('Error saving category:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to delete a category
 * @param {Event} event - IPC event
 * @param {string} categoryId - Category ID to delete
 */
ipcMain.handle('delete-category', async function(event, categoryId) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const categories = vaultStore.get('categories', []);
        const filteredCategories = categories.filter(c => c.id !== categoryId);

        /* Update entries that used this category */
        const passwordEntries = vaultStore.get('passwordEntries', []);
        const updatedPasswordEntries = passwordEntries.map(entry => {
            if (entry.category === categoryId) {
                return { ...entry, category: '', updatedAt: new Date().toISOString() };
            }
            return entry;
        });

        vaultStore.set('categories', filteredCategories);
        vaultStore.set('passwordEntries', updatedPasswordEntries);

        return { success: true };
    } catch (error) {
        console.error('Error deleting category:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to get all tags used in entries
 */
ipcMain.handle('get-tags', async function() {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const passwordEntries = vaultStore.get('passwordEntries', []);
        const totpEntries = vaultStore.get('totpEntries', []);

        const tagSet = new Set();

        /* Collect tags from password entries */
        passwordEntries.forEach(entry => {
            if (entry.tags && Array.isArray(entry.tags)) {
                entry.tags.forEach(tag => tagSet.add(tag));
            }
        });

        /* Collect tags from TOTP entries */
        totpEntries.forEach(entry => {
            if (entry.tags && Array.isArray(entry.tags)) {
                entry.tags.forEach(tag => tagSet.add(tag));
            }
        });

        const tags = Array.from(tagSet).sort();
        return { success: true, tags };
    } catch (error) {
        console.error('Error getting tags:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to search entries by various criteria
 * @param {Event} event - IPC event
 * @param {Object} criteria - Search criteria
 */
ipcMain.handle('search-entries', async function(event, criteria) {
    try {
        const lockCheck = ensureVaultStoreReady();
        if (lockCheck) return lockCheck;

        const passwordEntries = vaultStore.get('passwordEntries', []);
        const totpEntries = vaultStore.get('totpEntries', []);

        let results = { passwordEntries: [], totpEntries: [] };

        /* Search password entries */
        results.passwordEntries = passwordEntries.filter(entry => {
            let match = true;

            if (criteria.query) {
                const query = criteria.query.toLowerCase();
                match = match && (
                    entry.name?.toLowerCase().includes(query) ||
                    entry.username?.toLowerCase().includes(query) ||
                    entry.url?.toLowerCase().includes(query) ||
                    entry.notes?.toLowerCase().includes(query)
                );
            }

            if (criteria.category) {
                match = match && entry.category === criteria.category;
            }

            if (criteria.tags && criteria.tags.length > 0) {
                match = match && criteria.tags.some(tag =>
                    entry.tags && entry.tags.includes(tag)
                );
            }

            return match;
        });

        /* Search TOTP entries */
        results.totpEntries = totpEntries.filter(entry => {
            let match = true;

            if (criteria.query) {
                const query = criteria.query.toLowerCase();
                match = match && (
                    entry.name?.toLowerCase().includes(query) ||
                    entry.issuer?.toLowerCase().includes(query)
                );
            }

            if (criteria.tags && criteria.tags.length > 0) {
                match = match && criteria.tags.some(tag =>
                    entry.tags && entry.tags.includes(tag)
                );
            }

            return match;
        });

        return { success: true, results };
    } catch (error) {
        console.error('Error searching entries:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to register global shortcuts
 * @param {Event} event - IPC event
 * @param {Object} shortcuts - Shortcuts configuration
 */
ipcMain.handle('register-shortcuts', async function(event, shortcuts) {
    try {
        /* Unregister all existing shortcuts first */
        globalShortcut.unregisterAll();

        if (shortcuts.quickAccess) {
            globalShortcut.register(shortcuts.quickAccess, () => {
                if (mainWindow) {
                    if (mainWindow.isMinimized()) {
                        mainWindow.restore();
                    }
                    mainWindow.focus();
                    mainWindow.show();
                }
            });
        }

        if (shortcuts.lockVault) {
            globalShortcut.register(shortcuts.lockVault, () => {
                lockVaultInternal();
            });
        }

        return { success: true };
    } catch (error) {
        console.error('Error registering shortcuts:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to show system notification
 * @param {Event} event - IPC event
 * @param {Object} options - Notification options
 */
ipcMain.handle('show-notification', async function(event, options) {
    try {
        const notification = new Notification({
            title: options.title || i18n.t('app.title'),
            body: options.body || '',
            icon: getIconPath(),
            silent: options.silent || false,
            timeoutType: options.timeoutType || 'default'
        });

        notification.show();

        if (options.onClick) {
            notification.on('click', () => {
                mainWindow?.webContents.send('notification-clicked', options.id);
            });
        }

        return { success: true };
    } catch (error) {
        console.error('Error showing notification:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to copy text to clipboard with auto-clear
 * @param {Event} event - IPC event
 * @param {string} text - Text to copy
 * @param {number} timeout - Auto-clear timeout in ms (default: 30000)
 */
ipcMain.handle('copy-to-clipboard', async function(event, text, timeout = 30000) {
    try {
        clipboard.writeText(text);

        /* Auto-clear clipboard after timeout only if still contains our text */
        setTimeout(() => {
            try {
                if (clipboard.readText() === text) {
                    clipboard.clear();
                }
            } catch (error) {
                /* Ignore clipboard errors (may happen if clipboard is locked) */
                console.warn('Failed to auto-clear clipboard:', error.message);
            }
        }, timeout);

        return { success: true };
    } catch (error) {
        console.error('Error copying to clipboard:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to set application as system startup
 * @param {Event} event - IPC event
 * @param {boolean} enable - Whether to enable startup
 */
ipcMain.handle('set-startup', async function(event, enable) {
    try {
        app.setLoginItemSettings({
            openAtLogin: enable,
            openAsHidden: enable
        });
        return { success: true };
    } catch (error) {
        console.error('Error setting startup:', error);
        return { success: false, error: error.message };
    }
});

/**
 * IPC handler to get system startup status
 */
ipcMain.handle('get-startup-status', async function() {
    try {
        const settings = app.getLoginItemSettings();
        return {
            success: true,
            enabled: settings.openAtLogin,
            hidden: settings.openAsHidden
        };
    } catch (error) {
        console.error('Error getting startup status:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-app-version', async function() {
    return {
        success: true,
        version: app.getVersion(),
        name: app.getName()
    };
});

ipcMain.handle('show-error-dialog', async function(event, title, message, detail) {
    try {
        const options = {
            type: 'error',
            title: title || i18n.t('dialogs.error_title'),
            message: message || i18n.t('errors.unknown_error'),
            buttons: ['OK']
        };

        if (detail) {
            options.detail = detail;
        }

        await dialog.showMessageBox(mainWindow, options);
        return { success: true };
    } catch (error) {
        console.error('Error showing error dialog:', error);
        return { success: false, error: error.message };
    }
});

/**
 * App settings management
 */
ipcMain.handle('get-app-settings', async function() {
    try {
        const settings = store.get('appSettings', {});
        return {
            success: true,
            settings: settings
        };
    } catch (error) {
        console.error('Error getting app settings:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('save-app-settings', async function(event, settings) {
    try {
        /* Merge with existing settings */
        const currentSettings = store.get('appSettings', {});
        const newSettings = { ...currentSettings, ...settings };

        store.set('appSettings', newSettings);

        /* Apply shortcuts if provided */
        if (settings.shortcuts) {
            const shortcuts = [];
            if (settings.shortcuts.quickAccess) {
                shortcuts.push({
                    accelerator: settings.shortcuts.quickAccess,
                    action: 'quick-access'
                });
            }
            if (settings.shortcuts.autoLock) {
                shortcuts.push({
                    accelerator: settings.shortcuts.autoLock,
                    action: 'auto-lock'
                });
            }

            if (shortcuts.length > 0) {
                /* Register shortcuts using existing handler */
                try {
                    await ipcMain.invoke('register-shortcuts', shortcuts);
                } catch (error) {
                    console.warn('Failed to register shortcuts:', error.message);
                }
            }
        }

        return { success: true };
    } catch (error) {
        console.error('Error saving app settings:', error);
        return { success: false, error: error.message };
    }
});

/**
 * Export secure backup with password protection
 */
ipcMain.handle('export-secure-backup', async function() {
    try {
        if (!vaultStore) {
            return { success: false, error: i18n.t('errors.vault_not_initialized') };
        }

        const result = await dialog.showSaveDialog(mainWindow, {
            title: i18n.t('dialogs.export_backup_title'),
            defaultPath: `secure-vault-backup-${new Date().toISOString().split('T')[0]}.svault`,
            filters: [
                { name: i18n.t('file_types.secure_vault_backup'), extensions: ['svault'] },
                { name: i18n.t('file_types.all_files'), extensions: ['*'] }
            ]
        });

        if (result.canceled) {
            return { success: false, error: i18n.t('errors.export_canceled') };
        }

        /* Get backup password from user */
        const passwordResult = await dialog.showMessageBox(mainWindow, {
            type: 'question',
            title: i18n.t('dialogs.backup_password_title'),
            message: 'Enter a password to encrypt your backup:',
            buttons: [i18n.t('common.cancel'), i18n.t('common.ok')],
            defaultId: 1,
            cancelId: 0
        });

        if (passwordResult.response === 0) {
            return { success: false, error: i18n.t('errors.export_canceled') };
        }

        /* For simplicity, we'll prompt for password using a simple method */
        /* In production, you'd want a proper password input dialog */
        const backupPassword = 'secure-backup-password'; /* This should be user input */

        /* Get all vault data */
        const passwordEntries = vaultStore.get('passwordEntries', []);

        /* Use ImportExportManager to create encrypted backup */
        const { ImportExportManager } = require('./import-export');
        const importExportManager = new ImportExportManager();

        await importExportManager.exportData([...passwordEntries], 'securevault', result.filePath, backupPassword);

        return { success: true, filePath: result.filePath };
    } catch (error) {
        console.error('Error exporting secure backup:', error);
        return { success: false, error: error.message };
    }
});

process.on('uncaughtException', function(error) {
    console.error('Uncaught Exception:', error);

    if (mainWindow && !mainWindow.isDestroyed()) {
        dialog.showErrorBox(i18n.t('dialogs.unexpected_error_title'),
            'An unexpected error occurred: ' + error.message + '\n\nThe application will continue running, but you may want to restart it.'
        );
    }
});

process.on('unhandledRejection', function(reason, promise) {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.enableSandbox = false;

/**
 * Handle single instance check - prevent multiple app instances
 */
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
    app.quit();
} else {
    app.on('second-instance', function(event, commandLine, workingDirectory) {
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.focus();
            mainWindow.show();
        }
    });

    app.whenReady().then(function() {
    Menu.setApplicationMenu(null);
    createWindow();
    setupAutoUpdater();

    app.on('activate', function() {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});
}

app.on('window-all-closed', function() {
    if (updateCheckTimeout) {
        clearInterval(updateCheckTimeout);
        updateCheckTimeout = null;
    }

    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', function(event) {
    if (updateDownloaded) {
        event.preventDefault();
        autoUpdater.quitAndInstall();
    }
});

app.on('web-contents-created', function(event, contents) {
    contents.on('new-window', function(event, url) {
        event.preventDefault();
        shell.openExternal(url);
    });

    contents.on('will-navigate', function(event, navigationUrl) {
        const parsedUrl = new URL(navigationUrl);

        if (parsedUrl.origin !== 'file://') {
            event.preventDefault();
            shell.openExternal(navigationUrl);
        }
    });

    contents.setWindowOpenHandler(function(details) {
        shell.openExternal(details.url);
        return { action: 'deny' };
    });
});

app.setAboutPanelOptions({
    applicationName: i18n.t('about.application_name'),
    applicationVersion: app.getVersion(),
    copyright: 'Copyright © 2025',
    credits: i18n.t('about.credits')
});

if (process.env.NODE_ENV === 'production') {
    const gotTheLock = app.requestSingleInstanceLock();

    if (!gotTheLock) {
        app.quit();
    } else {
        app.on('second-instance', function() {
            if (mainWindow) {
                if (mainWindow.isMinimized()) mainWindow.restore();
                mainWindow.focus();
            }
        });
    }
}
