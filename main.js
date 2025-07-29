const { app, BrowserWindow, ipcMain, dialog, shell, Menu, desktopCapturer } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const bcrypt = require('bcrypt');
const Store = require('electron-store');

let mainWindow;
let updateDownloaded = false;
let isLocked = true;
let masterPasswordHash = null;
let updateCheckTimeout = null;

const store = new Store({
    name: 'secure-vault-config',
    encryptionKey: process.env.NODE_ENV === 'development' ? 'dev-key' : undefined
});

const vaultStore = new Store({
    name: 'secure-vault-data',
    encryptionKey: 'vault-data'
});

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
        title: 'Secure Vault'
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
            }
        }, 2000);
    });

    mainWindow.on('closed', function() {
        mainWindow = null;
        if (updateCheckTimeout) {
            clearTimeout(updateCheckTimeout);
        }
    });

    mainWindow.webContents.setWindowOpenHandler(function(details) {
        shell.openExternal(details.url);
        return { action: 'deny' };
    });
}

function getIconPath() {
    const iconPaths = {
        win32: 'assets/icon.ico',
        darwin: 'assets/icon.icns',
        linux: 'assets/icon.png'
    };

    const iconPath = iconPaths[process.platform] || iconPaths.linux;
    return path.join(__dirname, iconPath);
}

function setupAutoUpdater() {
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;

    autoUpdater.on('checking-for-update', function() {
        console.log('Checking for update...');
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-checking');
        }
    });

    autoUpdater.on('update-available', function(info) {
        console.log('Update available:', info);
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-available', info);
        }
    });

    autoUpdater.on('update-not-available', function(info) {
        console.log('Update not available:', info);
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-not-available', info);
        }
    });

    autoUpdater.on('error', function(err) {
        console.error('Update error:', err);
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
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-downloaded', info);
        }
    });
}

async function checkForUpdatesOnStartup() {
    try {
        const autoCheckEnabled = store.get('autoCheckUpdates', true);
        if (!autoCheckEnabled) {
            return;
        }

        const lastCheck = store.get('lastUpdateCheck', 0);
        const now = Date.now();
        const oneDayMs = 24 * 60 * 60 * 1000;

        if (now - lastCheck < oneDayMs) {
            return;
        }

        store.set('lastUpdateCheck', now);

        if (process.platform !== 'linux') {
            console.log('Checking for updates on startup...');
            await autoUpdater.checkForUpdates();
        }
    } catch (error) {
        console.error('Error checking for updates on startup:', error);
    }
}

function checkForUpdates() {
    if (process.platform === 'linux') {
        return Promise.resolve({ success: false, error: 'Updates not supported on Linux' });
    }

    try {
        return autoUpdater.checkForUpdates();
    } catch (error) {
        console.error('Error checking for updates:', error);
        throw error;
    }
}

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
            return { success: false, error: 'Source not found' };
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

ipcMain.handle('check-for-updates', async function() {
    try {
        const result = await autoUpdater.checkForUpdates();
        return { success: true, updateInfo: result };
    } catch (error) {
        console.error('Error checking for updates:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('download-update', async function() {
    try {
        await autoUpdater.downloadUpdate();
        return { success: true };
    } catch (error) {
        console.error('Error downloading update:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('install-update', async function() {
    try {
        if (updateDownloaded) {
            autoUpdater.quitAndInstall();
            return { success: true };
        } else {
            return { success: false, error: 'No update downloaded' };
        }
    } catch (error) {
        console.error('Error installing update:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-update-info', async function() {
    try {
        return {
            success: true,
            version: app.getVersion(),
            updateDownloaded: updateDownloaded,
            platform: process.platform,
            autoCheckEnabled: store.get('autoCheckUpdates', true),
            lastCheck: store.get('lastUpdateCheck', 0)
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('set-auto-check-updates', async function(event, enabled) {
    try {
        store.set('autoCheckUpdates', enabled);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('window-minimize', function() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.minimize();
    }
    return { success: true };
});

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

ipcMain.handle('window-close', function() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.close();
    }
    return { success: true };
});

ipcMain.handle('window-is-maximized', function() {
    return mainWindow && !mainWindow.isDestroyed() ? mainWindow.isMaximized() : false;
});

ipcMain.handle('setup-master-password', async function(event, password) {
    try {
        const saltRounds = 12;
        const hash = await bcrypt.hash(password, saltRounds);

        store.set('masterPasswordHash', hash);
        store.set('isSetup', true);

        masterPasswordHash = hash;
        isLocked = false;

        return { success: true };
    } catch (error) {
        console.error('Error setting up master password:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('verify-master-password', async function(event, password) {
    try {
        const storedHash = store.get('masterPasswordHash');
        if (!storedHash) {
            return { success: false, error: 'Master password not set' };
        }

        const isValid = await bcrypt.compare(password, storedHash);
        if (isValid) {
            masterPasswordHash = storedHash;
            isLocked = false;
            return { success: true };
        } else {
            return { success: false, error: 'Invalid password' };
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
            return { success: false, error: 'Master password not set' };
        }

        const isValid = await bcrypt.compare(currentPassword, storedHash);
        if (!isValid) {
            return { success: false, error: 'Current password is incorrect' };
        }

        const saltRounds = 12;
        const newHash = await bcrypt.hash(newPassword, saltRounds);

        store.set('masterPasswordHash', newHash);
        masterPasswordHash = newHash;

        return { success: true };
    } catch (error) {
        console.error('Error changing master password:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('lock-vault', async function() {
    try {
        isLocked = true;
        masterPasswordHash = null;
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
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

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
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

        const entries = vaultStore.get('passwordEntries', []);
        return { success: true, entries: entries };
    } catch (error) {
        console.error('Error getting password entries:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('delete-password-entry', async function(event, entryId) {
    try {
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

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
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

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
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

        const entries = vaultStore.get('totpEntries', []);
        return { success: true, entries: entries };
    } catch (error) {
        console.error('Error getting TOTP entries:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('delete-totp-entry', async function(event, entryId) {
    try {
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

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

ipcMain.handle('export-vault', async function() {
    try {
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Vault Data',
            defaultPath: 'secure-vault-backup-' + new Date().toISOString().split('T')[0] + '.json',
            filters: [
                { name: 'JSON Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        });

        if (result.canceled) {
            return { success: false, canceled: true };
        }

        const vaultData = {
            passwordEntries: vaultStore.get('passwordEntries', []),
            totpEntries: vaultStore.get('totpEntries', []),
            exportedAt: new Date().toISOString(),
            version: app.getVersion()
        };

        await fs.writeFile(result.filePath, JSON.stringify(vaultData, null, 2), 'utf8');
        return { success: true, path: result.filePath };
    } catch (error) {
        console.error('Error exporting vault:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('import-vault', async function() {
    try {
        if (isLocked) {
            return { success: false, error: 'Vault is locked' };
        }

        const result = await dialog.showOpenDialog(mainWindow, {
            title: 'Import Vault Data',
            filters: [
                { name: 'JSON Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ],
            properties: ['openFile']
        });

        if (result.canceled) {
            return { success: false, canceled: true };
        }

        const data = await fs.readFile(result.filePaths[0], 'utf8');
        const vaultData = JSON.parse(data);

        if (vaultData.passwordEntries) {
            const currentPasswordEntries = vaultStore.get('passwordEntries', []);
            const mergedPasswordEntries = currentPasswordEntries.concat(vaultData.passwordEntries);
            vaultStore.set('passwordEntries', mergedPasswordEntries);
        }

        if (vaultData.totpEntries) {
            const currentTotpEntries = vaultStore.get('totpEntries', []);
            const mergedTotpEntries = currentTotpEntries.concat(vaultData.totpEntries);
            vaultStore.set('totpEntries', mergedTotpEntries);
        }

        return { success: true, path: result.filePaths[0] };
    } catch (error) {
        console.error('Error importing vault:', error);
        return { success: false, error: error.message };
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
            title: title || 'Error',
            message: message || 'An unknown error occurred',
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

process.on('uncaughtException', function(error) {
    console.error('Uncaught Exception:', error);

    if (mainWindow && !mainWindow.isDestroyed()) {
        dialog.showErrorBox('Unexpected Error',
            'An unexpected error occurred: ' + error.message + '\n\nThe application will continue running, but you may want to restart it.'
        );
    }
});

process.on('unhandledRejection', function(reason, promise) {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.enableSandbox = false;

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

app.on('window-all-closed', function() {
    if (updateCheckTimeout) {
        clearTimeout(updateCheckTimeout);
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
    applicationName: 'Secure Vault',
    applicationVersion: app.getVersion(),
    copyright: 'Copyright © 2025',
    credits: 'Built with Electron and modern encryption'
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