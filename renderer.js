/**
 * @fileoverview Renderer process for Secure Vault - handles UI interactions and state management
 */

const { ipcRenderer } = require('electron');
const speakeasy = require('speakeasy');
const zxcvbn = require('zxcvbn');
const jsQR = require('jsqr');

/**
 * @typedef {Object} AppState
 * @property {boolean} isUnlocked - Whether the vault is unlocked
 * @property {Array} passwords - Array of password entries
 * @property {Array} totpAccounts - Array of TOTP authentication accounts
 * @property {Object} settings - Application settings
 * @property {string} searchQuery - Current search query
 * @property {string} selectedCategory - Currently selected password category
 * @property {string|null} editingPassword - ID of password being edited
 * @property {string|null} editingTotp - ID of TOTP account being edited
 * @property {string} totpModalMode - Mode for TOTP modal ('manual' or 'qr')
 * @property {NodeJS.Timeout|null} qrScanningTimeout - Timeout for QR scanning
 * @property {NodeJS.Timeout|null} screenCaptureInterval - Interval for screen capture
 * @property {Object} updateInfo - Information about app updates
 * @property {NodeJS.Timeout|null} autoLockTimer - Timer for auto-lock functionality
 * @property {Map} clipboardTimers - Map of clipboard clear timers
 * @property {Object} deleteModal - State for delete confirmation modal
 */
let appState = {
    isUnlocked: false,
    passwords: [],
    totpAccounts: [],
    settings: {
        autoLock: true,
        autoLockTime: 15,
        clearClipboard: true,
        clipboardTimeout: 30,
        autoBackup: false,
        autoCheckUpdates: true
    },
    searchQuery: '',
    selectedCategory: '',
    editingPassword: null,
    editingTotp: null,
    totpModalMode: 'manual',
    qrScanningTimeout: null,
    screenCaptureInterval: null,
    updateInfo: {
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
        error: null
    },
    autoLockTimer: null,
    clipboardTimers: new Map(),
    deleteModal: {
        isOpen: false,
        type: null,
        itemId: null,
        itemName: ''
    }
};

const elements = {
    lockScreen: document.getElementById('lock-screen'),
    appHeader: document.getElementById('app-header'),
    appMain: document.getElementById('app-main'),
    setupForm: document.getElementById('setup-form'),
    unlockForm: document.getElementById('unlock-form'),

    setupPassword: document.getElementById('setup-password'),
    setupPasswordConfirm: document.getElementById('setup-password-confirm'),
    setupPasswordToggle: document.getElementById('setup-password-toggle'),
    setupPasswordConfirmToggle: document.getElementById('setup-password-confirm-toggle'),
    setupPasswordStrength: document.getElementById('setup-password-strength'),
    setupVaultBtn: document.getElementById('setup-vault-btn'),

    masterPassword: document.getElementById('master-password'),
    masterPasswordToggle: document.getElementById('master-password-toggle'),
    unlockVaultBtn: document.getElementById('unlock-vault-btn'),

    lockVaultBtn: document.getElementById('lock-vault-btn'),

    navItems: document.querySelectorAll('.nav-item'),
    tabContents: document.querySelectorAll('.tab-content'),

    passwordSearch: document.getElementById('password-search'),
    passwordCategoryFilter: document.getElementById('password-category-filter'),
    addPasswordBtn: document.getElementById('add-password-btn'),
    addFirstPasswordBtn: document.getElementById('add-first-password-btn'),
    passwordList: document.getElementById('password-list'),
    passwordEmptyState: document.getElementById('password-empty-state'),
    passwordCount: document.getElementById('password-count'),

    addTotpBtn: document.getElementById('add-totp-btn'),
    addTotpManualBtn: document.getElementById('add-totp-manual-btn'),
    addFirstTotpBtn: document.getElementById('add-first-totp-btn'),
    totpList: document.getElementById('totp-list'),
    totpEmptyState: document.getElementById('totp-empty-state'),
    totpCount: document.getElementById('totp-count'),

    changeMasterPasswordBtn: document.getElementById('change-master-password-btn'),
    exportVaultBtn: document.getElementById('export-vault-btn'),
    importVaultBtn: document.getElementById('import-vault-btn'),
    autoLock: document.getElementById('auto-lock'),
    autoLockTime: document.getElementById('auto-lock-time'),
    clearClipboard: document.getElementById('clear-clipboard'),
    clipboardTimeout: document.getElementById('clipboard-timeout'),
    autoBackup: document.getElementById('auto-backup'),

    passwordModal: document.getElementById('password-modal'),
    passwordModalTitle: document.getElementById('password-modal-title'),
    passwordForm: document.getElementById('password-form'),
    passwordName: document.getElementById('password-name'),
    passwordUsername: document.getElementById('password-username'),
    passwordPassword: document.getElementById('password-password'),
    passwordPasswordToggle: document.getElementById('password-password-toggle'),
    generatePasswordBtn: document.getElementById('generate-password-btn'),
    passwordStrength: document.getElementById('password-strength'),
    passwordUrl: document.getElementById('password-url'),
    passwordCategory: document.getElementById('password-category'),
    passwordNotes: document.getElementById('password-notes'),
    passwordModalCancel: document.getElementById('password-modal-cancel'),
    passwordModalSave: document.getElementById('password-modal-save'),

    totpModal: document.getElementById('totp-modal'),
    totpModalTitle: document.getElementById('totp-modal-title'),
    totpForm: document.getElementById('totp-form'),
    totpName: document.getElementById('totp-name'),
    totpIssuer: document.getElementById('totp-issuer'),
    totpSecret: document.getElementById('totp-secret'),
    totpDigits: document.getElementById('totp-digits'),
    totpPeriod: document.getElementById('totp-period'),
    totpModalCancel: document.getElementById('totp-modal-cancel'),
    totpModalSave: document.getElementById('totp-modal-save'),

    changePasswordModal: document.getElementById('change-password-modal'),
    changePasswordForm: document.getElementById('change-password-form'),
    currentMasterPassword: document.getElementById('current-master-password'),
    currentMasterPasswordToggle: document.getElementById('current-master-password-toggle'),
    newMasterPassword: document.getElementById('new-master-password'),
    newMasterPasswordToggle: document.getElementById('new-master-password-toggle'),
    newPasswordStrength: document.getElementById('new-password-strength'),
    confirmNewMasterPassword: document.getElementById('confirm-new-master-password'),
    confirmNewMasterPasswordToggle: document.getElementById('confirm-new-master-password-toggle'),
    changePasswordModalCancel: document.getElementById('change-password-modal-cancel'),
    changePasswordModalSave: document.getElementById('change-password-modal-save'),

    deleteModal: document.getElementById('delete-modal'),
    deleteMessage: document.getElementById('delete-message'),
    deleteItemLabel: document.getElementById('delete-item-label'),
    deleteItemName: document.getElementById('delete-item-name'),
    deleteModalCancel: document.getElementById('delete-modal-cancel'),
    deleteModalConfirm: document.getElementById('delete-modal-confirm'),

    minimizeBtn: document.getElementById('minimize-btn'),
    maximizeBtn: document.getElementById('maximize-btn'),
    closeBtn: document.getElementById('close-btn'),

    languageSelector: document.getElementById('language-selector'),
    checkUpdatesBtn: document.getElementById('check-updates-btn'),
    manualCheckUpdatesBtn: document.getElementById('manual-check-updates'),
    autoCheckUpdates: document.getElementById('auto-check-updates'),
    currentVersion: document.getElementById('current-version'),
    updateStatus: document.getElementById('update-status'),

    updateModal: document.getElementById('update-modal'),
    modalCurrentVersion: document.getElementById('modal-current-version'),
    modalNewVersion: document.getElementById('modal-new-version'),
    releaseNotesContent: document.getElementById('release-notes-content'),
    downloadProgress: document.getElementById('download-progress'),
    downloadPercentage: document.getElementById('download-percentage'),
    downloadProgressFill: document.getElementById('download-progress-fill'),
    skipUpdateBtn: document.getElementById('skip-update'),
    installLaterBtn: document.getElementById('install-later'),
    installUpdateBtn: document.getElementById('install-update')
};

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * Initializes the application by setting up event handlers, loading settings, and checking vault status
 */
async function initializeApp() {
    setupEventListeners();
    setupWindowControls();
    setupUpdateHandlers();
    loadSettings();
    loadAppVersion();
    await loadUpdateSettings();
    await checkVaultSetup();

    if (typeof i18n !== 'undefined') {
        setupLanguageHandling();
    } else {
        setTimeout(function() {
            if (typeof i18n !== 'undefined') {
                setupLanguageHandling();
            }
        }, 100);
    }
}

function setupLanguageHandling() {
    if (elements.languageSelector) {
        elements.languageSelector.addEventListener('change', function(e) {
            i18n.setLanguage(e.target.value);
        });
    }
}

function setupEventListeners() {
    elements.navItems.forEach(function(item) {
        item.addEventListener('click', function() {
            const tabId = item.getAttribute('data-tab');
            switchTab(tabId);
        });
    });

    if (elements.setupVaultBtn) elements.setupVaultBtn.addEventListener('click', setupVault);
    if (elements.unlockVaultBtn) elements.unlockVaultBtn.addEventListener('click', unlockVault);
    if (elements.lockVaultBtn) elements.lockVaultBtn.addEventListener('click', lockVault);

    if (elements.setupPasswordToggle) elements.setupPasswordToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.setupPassword, elements.setupPasswordToggle);
    });
    if (elements.setupPasswordConfirmToggle) elements.setupPasswordConfirmToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.setupPasswordConfirm, elements.setupPasswordConfirmToggle);
    });
    if (elements.masterPasswordToggle) elements.masterPasswordToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.masterPassword, elements.masterPasswordToggle);
    });

    if (elements.setupPassword) elements.setupPassword.addEventListener('input', function() {
        updatePasswordStrength(elements.setupPassword, elements.setupPasswordStrength);
    });

    if (elements.setupPassword) elements.setupPassword.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            elements.setupPasswordConfirm.focus();
        }
    });

    if (elements.setupPasswordConfirm) elements.setupPasswordConfirm.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            setupVault();
        }
    });

    if (elements.masterPassword) elements.masterPassword.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            unlockVault();
        }
    });

    if (elements.passwordSearch) elements.passwordSearch.addEventListener('input', async function(e) {
        appState.searchQuery = e.target.value.toLowerCase();
        await filterPasswords();
    });

    if (elements.passwordCategoryFilter) elements.passwordCategoryFilter.addEventListener('change', async function(e) {
        appState.selectedCategory = e.target.value;
        await filterPasswords();
    });

    if (elements.addPasswordBtn) elements.addPasswordBtn.addEventListener('click', async function() { await openPasswordModal(); });
    if (elements.addFirstPasswordBtn) elements.addFirstPasswordBtn.addEventListener('click', async function() { await openPasswordModal(); });

    if (elements.addTotpBtn) elements.addTotpBtn.addEventListener('click', function() { openTotpModal(null, 'qr'); });
    if (elements.addTotpManualBtn) elements.addTotpManualBtn.addEventListener('click', function() { openTotpModal(null, 'manual'); });
    if (elements.addFirstTotpBtn) elements.addFirstTotpBtn.addEventListener('click', function() { openTotpModal(null, 'qr'); });

    if (elements.passwordModalCancel) elements.passwordModalCancel.addEventListener('click', closePasswordModal);
    if (elements.passwordModalSave) elements.passwordModalSave.addEventListener('click', savePassword);
    if (elements.passwordPasswordToggle) elements.passwordPasswordToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.passwordPassword, elements.passwordPasswordToggle);
    });
    if (elements.generatePasswordBtn) elements.generatePasswordBtn.addEventListener('click', generatePassword);
    if (elements.passwordPassword) elements.passwordPassword.addEventListener('input', function() {
        updatePasswordStrength(elements.passwordPassword, elements.passwordStrength);
    });

    if (elements.totpModalCancel) elements.totpModalCancel.addEventListener('click', closeTotpModal);
    if (elements.totpModalSave) elements.totpModalSave.addEventListener('click', saveTotp);

    if (elements.changeMasterPasswordBtn) elements.changeMasterPasswordBtn.addEventListener('click', openChangePasswordModal);
    if (elements.changePasswordModalCancel) elements.changePasswordModalCancel.addEventListener('click', closeChangePasswordModal);
    if (elements.changePasswordModalSave) elements.changePasswordModalSave.addEventListener('click', changeMasterPassword);
    if (elements.currentMasterPasswordToggle) elements.currentMasterPasswordToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.currentMasterPassword, elements.currentMasterPasswordToggle);
    });
    if (elements.newMasterPasswordToggle) elements.newMasterPasswordToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.newMasterPassword, elements.newMasterPasswordToggle);
    });
    if (elements.confirmNewMasterPasswordToggle) elements.confirmNewMasterPasswordToggle.addEventListener('click', function() {
        togglePasswordVisibility(elements.confirmNewMasterPassword, elements.confirmNewMasterPasswordToggle);
    });
    if (elements.newMasterPassword) elements.newMasterPassword.addEventListener('input', function() {
        updatePasswordStrength(elements.newMasterPassword, elements.newPasswordStrength);
    });

    if (elements.deleteModalCancel) elements.deleteModalCancel.addEventListener('click', closeDeleteModal);
    if (elements.deleteModalConfirm) elements.deleteModalConfirm.addEventListener('click', confirmDelete);

    if (elements.exportVaultBtn) elements.exportVaultBtn.addEventListener('click', exportVault);
    if (elements.importVaultBtn) elements.importVaultBtn.addEventListener('click', importVault);

    setupSettingsEventListeners();
    setupModalEventListeners();
    setupUserActivityTracking();
}

function setupWindowControls() {
    if (elements.minimizeBtn) elements.minimizeBtn.addEventListener('click', function() {
        ipcRenderer.invoke('window-minimize');
    });

    if (elements.maximizeBtn) elements.maximizeBtn.addEventListener('click', function() {
        ipcRenderer.invoke('window-maximize');
    });

    if (elements.closeBtn) elements.closeBtn.addEventListener('click', function() {
        ipcRenderer.invoke('window-close');
    });
}

function setupUpdateHandlers() {
    if (elements.checkUpdatesBtn) elements.checkUpdatesBtn.addEventListener('click', checkForUpdates);
    if (elements.manualCheckUpdatesBtn) elements.manualCheckUpdatesBtn.addEventListener('click', checkForUpdates);

    if (elements.autoCheckUpdates) elements.autoCheckUpdates.addEventListener('change', async function(e) {
        appState.settings.autoCheckUpdates = e.target.checked;
        saveSettings();
        await ipcRenderer.invoke('set-auto-check-updates', e.target.checked);
    });

    if (elements.skipUpdateBtn) elements.skipUpdateBtn.addEventListener('click', function() {
        hideUpdateModal();
    });

    if (elements.installLaterBtn) elements.installLaterBtn.addEventListener('click', function() {
        hideUpdateModal();
    });

    if (elements.installUpdateBtn) elements.installUpdateBtn.addEventListener('click', function() {
        if (appState.updateInfo.downloaded) {
            installUpdate();
        } else {
            downloadUpdate();
        }
    });

    ipcRenderer.on('update-checking', function() {
        appState.updateInfo.checking = true;
        updateUpdateStatus();
        if (appState.isUnlocked) {
            showToast(i18n.t('toast.update_checking'), 'info');
        }
    });

    ipcRenderer.on('update-available', function(_event, info) {
        appState.updateInfo = {
            checking: false,
            available: true,
            downloading: false,
            downloaded: false,
            error: null,
            info: info
        };
        updateUpdateStatus();
        if (appState.isUnlocked) {
            showUpdateModal(info);
            showToast(i18n.t('toast.update_available'), 'success');
        }
    });

    ipcRenderer.on('update-not-available', function() {
        appState.updateInfo = {
            checking: false,
            available: false,
            downloading: false,
            downloaded: false,
            error: null
        };
        updateUpdateStatus();
    });

    ipcRenderer.on('update-error', function(event, error) {
        appState.updateInfo = {
            checking: false,
            available: false,
            downloading: false,
            downloaded: false,
            error: error
        };
        updateUpdateStatus();
        if (appState.isUnlocked) {
            showToast(i18n.t('toast.update_error'), 'error');
        }
    });

    ipcRenderer.on('update-download-progress', function(event, progressObj) {
        updateDownloadProgress(progressObj);
    });

    ipcRenderer.on('update-downloaded', function() {
        appState.updateInfo.downloading = false;
        appState.updateInfo.downloaded = true;
        updateUpdateStatus();
        updateInstallButton();
        if (appState.isUnlocked) {
            showToast(i18n.t('toast.update_downloaded'), 'success');
            showUpdateReadyNotification();
        }
    });

    ipcRenderer.on('vault-auto-locked', function() {
        if (appState.isUnlocked) {
            lockVault();
            showToast(i18n.t('toast.auto_locked'), 'info');
        }
    });
}

function setupSettingsEventListeners() {
    if (elements.autoLock) elements.autoLock.addEventListener('change', function(e) {
        appState.settings.autoLock = e.target.checked;
        saveSettings();
        if (e.target.checked) {
            startAutoLockTimer();
        } else {
            clearAutoLockTimer();
        }
    });

    if (elements.autoLockTime) elements.autoLockTime.addEventListener('change', function(e) {
        appState.settings.autoLockTime = parseInt(e.target.value);
        saveSettings();
        if (appState.settings.autoLock) {
            startAutoLockTimer();
        }
    });

    if (elements.clearClipboard) elements.clearClipboard.addEventListener('change', function(e) {
        appState.settings.clearClipboard = e.target.checked;
        saveSettings();
    });

    if (elements.clipboardTimeout) elements.clipboardTimeout.addEventListener('change', function(e) {
        appState.settings.clipboardTimeout = parseInt(e.target.value);
        saveSettings();
    });

    if (elements.autoBackup) elements.autoBackup.addEventListener('change', function(e) {
        appState.settings.autoBackup = e.target.checked;
        saveSettings();
    });
}

function setupModalEventListeners() {
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            if (e.target === elements.passwordModal) {
                closePasswordModal();
            } else if (e.target === elements.totpModal) {
                closeTotpModal();
            } else if (e.target === elements.changePasswordModal) {
                closeChangePasswordModal();
            } else if (e.target === elements.deleteModal) {
                closeDeleteModal();
            } else if (e.target === elements.updateModal) {
                hideUpdateModal();
            } else if (e.target.id === 'import-export-modal') {
                closeImportExportModal();
            } else if (e.target.id === 'audit-modal') {
                closeAuditModal();
            } else if (e.target.id === 'category-modal') {
                closeCategoryModal();
            } else if (e.target.id === 'search-modal') {
                closeSearchModal();
            }
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            if (elements.passwordModal.style.display === 'block') {
                closePasswordModal();
            } else if (elements.totpModal.style.display === 'block') {
                closeTotpModal();
            } else if (elements.changePasswordModal.style.display === 'block') {
                closeChangePasswordModal();
            } else if (elements.deleteModal.style.display === 'block') {
                closeDeleteModal();
            } else if (elements.updateModal.style.display === 'block') {
                hideUpdateModal();
            } else if (document.getElementById('import-export-modal').style.display === 'block') {
                closeImportExportModal();
            } else if (document.getElementById('audit-modal').style.display === 'block') {
                closeAuditModal();
            } else if (document.getElementById('category-modal').style.display === 'block') {
                closeCategoryModal();
            } else if (document.getElementById('search-modal').style.display === 'block') {
                closeSearchModal();
            }
        }
    });
}

function setupUserActivityTracking() {
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];

    events.forEach(function(event) {
        document.addEventListener(event, function() {
            if (appState.isUnlocked && appState.settings.autoLock) {
                startAutoLockTimer();
            }
        });
    });
}

async function checkVaultSetup() {
    try {
        const result = await ipcRenderer.invoke('is-vault-setup');
        if (result.success) {
            if (!result.isSetup) {
                showSetupForm();
            } else if (result.isLocked) {
                showUnlockForm();
            } else {
                await unlockApplication();
            }
        }
    } catch (error) {
        showSetupForm();
    }
}

function showSetupForm() {
    elements.setupForm.style.display = 'block';
    elements.unlockForm.style.display = 'none';
    elements.lockScreen.style.display = 'flex';
    elements.appHeader.style.display = 'none';
    elements.appMain.style.display = 'none';
    setTimeout(function() {
        if (elements.setupPassword) elements.setupPassword.focus();
    }, 100);
}

function showUnlockForm() {
    elements.setupForm.style.display = 'none';
    elements.unlockForm.style.display = 'block';
    elements.lockScreen.style.display = 'flex';
    elements.appHeader.style.display = 'none';
    elements.appMain.style.display = 'none';
    setTimeout(function() {
        if (elements.masterPassword) elements.masterPassword.focus();
    }, 100);
}

async function setupVault() {
    const password = elements.setupPassword ? elements.setupPassword.value : '';
    const confirmPassword = elements.setupPasswordConfirm ? elements.setupPasswordConfirm.value : '';

    if (!password || !confirmPassword) {
        showToast(i18n.t('common.fill_all_fields'), 'error');
        return;
    }

    if (password !== confirmPassword) {
        showToast(i18n.t('toast.passwords_dont_match'), 'error');
        return;
    }

    const strength = zxcvbn(password);
    if (strength.score < 3) {
        showToast(i18n.t('toast.weak_password'), 'error');
        return;
    }

    try {
        elements.setupVaultBtn.disabled = true;
        const result = await ipcRenderer.invoke('setup-master-password', password);

        if (result.success) {
            showToast(i18n.t('toast.vault_created'), 'success');
            await unlockApplication();
        } else {
            showToast(result.error || i18n.t('toast.setup_vault_failed'), 'error');
        }
    } catch (error) {
        showToast(i18n.t('toast.setup_vault_failed'), 'error');
    } finally {
        elements.setupVaultBtn.disabled = false;
    }
}

async function unlockVault() {
    const password = elements.masterPassword ? elements.masterPassword.value : '';

    if (!password) {
        showToast(i18n.t('common.enter_master_password'), 'error');
        return;
    }

    try {
        elements.unlockVaultBtn.disabled = true;
        const result = await ipcRenderer.invoke('verify-master-password', password);

        if (result.success) {
            showToast(i18n.t('toast.vault_unlocked'), 'success');
            await unlockApplication();
        } else {
            showToast(i18n.t('toast.invalid_master_password'), 'error');
            elements.masterPassword.value = '';
            elements.masterPassword.focus();
        }
    } catch (error) {
        console.error('Error unlocking vault:', error);
        showToast(i18n.t('toast.unlock_vault_failed'), 'error');
    } finally {
        elements.unlockVaultBtn.disabled = false;
    }
}

async function lockVault() {
    try {
        await ipcRenderer.invoke('lock-vault');
        appState.isUnlocked = false;
        appState.passwords = [];
        appState.totpAccounts = [];
        clearAutoLockTimer();
        clearAllClipboardTimers();
        stopDesktopCapture();

        elements.lockScreen.style.display = 'flex';
        elements.appHeader.style.display = 'none';
        elements.appMain.style.display = 'none';

        showUnlockForm();
        showToast(i18n.t('toast.vault_locked'), 'info');
    } catch (error) {
        console.error('Error locking vault:', error);
        showToast(i18n.t('toast.lock_vault_failed'), 'error');
    }
}

async function unlockApplication() {
    appState.isUnlocked = true;

    elements.lockScreen.style.display = 'none';
    elements.appHeader.style.display = 'block';
    elements.appMain.style.display = 'flex';

    if (elements.setupPassword) elements.setupPassword.value = '';
    if (elements.setupPasswordConfirm) elements.setupPasswordConfirm.value = '';
    if (elements.masterPassword) elements.masterPassword.value = '';

    await loadPasswords();
    await loadTotpAccounts();
    await populateCategoryDropdowns();
    updateUI();

    if (appState.settings.autoLock) {
        startAutoLockTimer();
    }

    startTotpCountdown();
}

function switchTab(tabId) {
    elements.navItems.forEach(function(item) {
        item.classList.remove('active');
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
        }
    });

    elements.tabContents.forEach(function(content) {
        content.classList.remove('active');
        if (content.id === tabId + '-tab') {
            content.classList.add('active');
        }
    });
}

async function loadPasswords() {
    try {
        const result = await ipcRenderer.invoke('get-password-entries');
        if (result.success) {
            appState.passwords = result.entries || [];
            updatePasswordList();
        }
    } catch (error) {
        console.error('Error loading passwords:', error);
    }
}

async function loadTotpAccounts() {
    try {
        const result = await ipcRenderer.invoke('get-totp-entries');
        if (result.success) {
            appState.totpAccounts = result.entries || [];
            updateTotpList();
        }
    } catch (error) {
        console.error('Error loading TOTP accounts:', error);
    }
}

async function updatePasswordList() {
    if (!elements.passwordList || !elements.passwordCount) return;

    let filteredPasswords = appState.passwords;

    if (appState.searchQuery) {
        filteredPasswords = filteredPasswords.filter(function(password) {
            return password.name.toLowerCase().includes(appState.searchQuery) ||
                   password.username.toLowerCase().includes(appState.searchQuery) ||
                   password.url.toLowerCase().includes(appState.searchQuery);
        });
    }

    if (appState.selectedCategory) {
        filteredPasswords = filteredPasswords.filter(function(password) {
            return password.category === appState.selectedCategory;
        });
    }

    elements.passwordCount.textContent = filteredPasswords.length.toString();

    if (filteredPasswords.length === 0) {
        elements.passwordEmptyState.style.display = 'block';
        elements.passwordList.innerHTML = '';
        return;
    }

    elements.passwordEmptyState.style.display = 'none';
    elements.passwordList.innerHTML = '';

    for (const password of filteredPasswords) {
        const passwordItem = await createPasswordItem(password);
        elements.passwordList.appendChild(passwordItem);
    }
}

async function createPasswordItem(password) {
    const item = document.createElement('div');
    item.className = 'password-item';

    const categoryIcon = await getCategoryIcon(password.category);
    const strengthClass = getPasswordStrengthClass(password.password);

    item.innerHTML =
        '<div class="password-item-header">' +
            '<div class="password-info">' +
                '<div class="password-icon">' +
                    '<i class="fas ' + categoryIcon + '"></i>' +
                '</div>' +
                '<div class="password-details">' +
                    '<div class="password-name">' + escapeHtml(password.name) + '</div>' +
                    '<div class="password-username">' + escapeHtml(password.username || '') + '</div>' +
                    (password.url ? '<div class="password-url">' + escapeHtml(password.url) + '</div>' : '') +
                '</div>' +
            '</div>' +
            '<div class="password-strength-indicator ' + strengthClass + '"></div>' +
        '</div>' +
        '<div class="password-actions">' +
            '<button class="btn btn-sm btn-outline" onclick="copyUsername(\'' + password.id + '\')" title="' + i18n.t('passwords.copy_username') + '">' +
                '<i class="fas fa-user"></i>' +
            '</button>' +
            '<button class="btn btn-sm btn-outline" onclick="copyPassword(\'' + password.id + '\')" title="' + i18n.t('passwords.copy_password') + '">' +
                '<i class="fas fa-key"></i>' +
            '</button>' +
            (password.url ? '<button class="btn btn-sm btn-outline" onclick="visitWebsite(\'' + password.id + '\')" title="' + i18n.t('passwords.visit_website') + '">' +
                '<i class="fas fa-external-link-alt"></i>' +
            '</button>' : '') +
            '<button class="btn btn-sm btn-outline" onclick="editPassword(\'' + password.id + '\')" title="' + i18n.t('passwords.edit_password') + '">' +
                '<i class="fas fa-edit"></i>' +
            '</button>' +
            '<button class="btn btn-sm btn-outline btn-danger" onclick="deletePassword(\'' + password.id + '\')" title="' + i18n.t('passwords.delete_password') + '">' +
                '<i class="fas fa-trash"></i>' +
            '</button>' +
        '</div>';

    return item;
}

function updateTotpList() {
    if (!elements.totpList || !elements.totpCount) return;

    elements.totpCount.textContent = appState.totpAccounts.length.toString();

    if (appState.totpAccounts.length === 0) {
        elements.totpEmptyState.style.display = 'block';
        elements.totpList.innerHTML = '';
        return;
    }

    elements.totpEmptyState.style.display = 'none';
    elements.totpList.innerHTML = '';

    appState.totpAccounts.forEach(function(account) {
        const totpItem = createTotpItem(account);
        elements.totpList.appendChild(totpItem);
    });
}

function createTotpItem(account) {
    const item = document.createElement('div');
    item.className = 'totp-item';

    const token = generateTotpCode(account);
    const timeRemaining = getTotpTimeRemaining(account.period || 30);

    item.innerHTML =
        '<div class="totp-item-header">' +
            '<div class="totp-info">' +
                '<div class="totp-icon">' +
                    '<i class="fas fa-shield-alt"></i>' +
                '</div>' +
                '<div class="totp-details">' +
                    '<div class="totp-name">' + escapeHtml(account.name) + '</div>' +
                    '<div class="totp-issuer">' + escapeHtml(account.issuer || '') + '</div>' +
                '</div>' +
            '</div>' +
            '<div class="totp-timer">' +
                '<div class="totp-countdown" data-period="' + (account.period || 30) + '">' +
                    '<span class="countdown-text">' + timeRemaining + 's</span>' +
                    '<div class="countdown-circle">' +
                        '<svg width="20" height="20">' +
                            '<circle cx="10" cy="10" r="8" stroke="#00d4ff" stroke-width="2" fill="none" stroke-dasharray="50.27" stroke-dashoffset="0"></circle>' +
                        '</svg>' +
                    '</div>' +
                '</div>' +
            '</div>' +
        '</div>' +
        '<div class="totp-code-container">' +
            '<div class="totp-code" data-account-id="' + account.id + '">' + token + '</div>' +
            '<div class="totp-actions">' +
                '<button class="btn btn-sm btn-outline" onclick="copyTotpCode(\'' + account.id + '\')" title="' + i18n.t('authenticator.copy_code') + '">' +
                    '<i class="fas fa-copy"></i>' +
                '</button>' +
                '<button class="btn btn-sm btn-outline" onclick="editTotp(\'' + account.id + '\')" title="' + i18n.t('authenticator.edit_account') + '">' +
                    '<i class="fas fa-edit"></i>' +
                '</button>' +
                '<button class="btn btn-sm btn-outline btn-danger" onclick="deleteTotp(\'' + account.id + '\')" title="' + i18n.t('authenticator.delete_account') + '">' +
                    '<i class="fas fa-trash"></i>' +
                '</button>' +
            '</div>' +
        '</div>';

    return item;
}

async function filterPasswords() {
    await updatePasswordList();
}

async function openPasswordModal(passwordId) {
    appState.editingPassword = passwordId;
    
    await populateCategoryDropdowns();

    if (passwordId) {
        const password = appState.passwords.find(function(p) {
            return p.id === passwordId;
        });
        if (password) {
            elements.passwordModalTitle.textContent = i18n.t('passwords.edit_password');
            elements.passwordName.value = password.name || '';
            elements.passwordUsername.value = password.username || '';
            elements.passwordPassword.value = password.password || '';
            elements.passwordUrl.value = password.url || '';
            elements.passwordCategory.value = password.category || 'website';
            elements.passwordNotes.value = password.notes || '';
        }
    } else {
        elements.passwordModalTitle.textContent = i18n.t('passwords.add_password');
        elements.passwordForm.reset();
    }

    elements.passwordModal.style.display = 'block';
    setTimeout(function() {
        if (elements.passwordName) elements.passwordName.focus();
    }, 100);
}

function closePasswordModal() {
    elements.passwordModal.style.display = 'none';
    appState.editingPassword = null;
    elements.passwordForm.reset();
}

async function savePassword() {
    const name = elements.passwordName ? elements.passwordName.value.trim() : '';
    const username = elements.passwordUsername ? elements.passwordUsername.value.trim() : '';
    const password = elements.passwordPassword ? elements.passwordPassword.value : '';
    const url = elements.passwordUrl ? elements.passwordUrl.value.trim() : '';
    const category = elements.passwordCategory ? elements.passwordCategory.value : '';
    const notes = elements.passwordNotes ? elements.passwordNotes.value.trim() : '';

    if (!name || !password) {
        showToast(i18n.t('common.name_password_required'), 'error');
        return;
    }

    const passwordEntry = {
        id: appState.editingPassword,
        name: name,
        username: username,
        password: password,
        url: url,
        category: category,
        notes: notes
    };

    try {
        elements.passwordModalSave.disabled = true;
        const result = await ipcRenderer.invoke('save-password-entry', passwordEntry);

        if (result.success) {
            showToast(i18n.t('toast.password_saved'), 'success');
            closePasswordModal();
            await loadPasswords();
        } else {
            showToast(result.error || i18n.t('toast.save_password_failed'), 'error');
        }
    } catch (error) {
        console.error('Error saving password:', error);
        showToast(i18n.t('toast.save_password_failed'), 'error');
    } finally {
        elements.passwordModalSave.disabled = false;
    }
}

function openDeleteModal(type, itemId, itemName) {
    appState.deleteModal = {
        isOpen: true,
        type: type,
        itemId: itemId,
        itemName: itemName
    };

    if (type === 'password') {
        elements.deleteMessage.textContent = i18n.t('delete.password_message');
        elements.deleteItemLabel.textContent = i18n.t('delete.password_name');
    } else if (type === 'account') {
        elements.deleteMessage.textContent = i18n.t('delete.account_message');
        elements.deleteItemLabel.textContent = i18n.t('delete.account_name');
    } else if (type === 'category') {
        elements.deleteMessage.textContent = i18n.t('delete.category_message');
        elements.deleteItemLabel.textContent = i18n.t('delete.category_name');
    }

    elements.deleteItemName.textContent = itemName;
    elements.deleteModal.style.display = 'block';
}

function closeDeleteModal() {
    elements.deleteModal.style.display = 'none';
    appState.deleteModal = {
        isOpen: false,
        type: null,
        itemId: null,
        itemName: ''
    };
}

async function confirmDelete() {
    if (!appState.deleteModal.isOpen) return;

    try {
        elements.deleteModalConfirm.disabled = true;

        if (appState.deleteModal.type === 'password') {
            const result = await ipcRenderer.invoke('delete-password-entry', appState.deleteModal.itemId);
            if (result.success) {
                showToast(i18n.t('toast.password_deleted'), 'success');
                await loadPasswords();
            } else {
                showToast(result.error || i18n.t('toast.delete_password_failed'), 'error');
            }
        } else if (appState.deleteModal.type === 'account') {
            const result = await ipcRenderer.invoke('delete-totp-entry', appState.deleteModal.itemId);
            if (result.success) {
                showToast(i18n.t('toast.account_deleted'), 'success');
                await loadTotpAccounts();
            } else {
                showToast(result.error || i18n.t('toast.delete_account_failed'), 'error');
            }
        } else if (appState.deleteModal.type === 'category') {
            const result = await ipcRenderer.invoke('delete-category', appState.deleteModal.itemId);
            if (result.success) {
                showToast(i18n.t('toast.category_deleted'), 'success');
                await loadCategories();
                await populateCategoryDropdowns();
                await openCategoryModal(); // Refresh the category modal
            } else {
                showToast(i18n.t('toast.category_delete_failed'), 'error');
            }
        }

        closeDeleteModal();
    } catch (error) {
        console.error('Error deleting item:', error);
        if (appState.deleteModal.type === 'password') {
            showToast(i18n.t('toast.delete_password_failed'), 'error');
        } else if (appState.deleteModal.type === 'account') {
            showToast(i18n.t('toast.delete_account_failed'), 'error');
        } else if (appState.deleteModal.type === 'category') {
            showToast(i18n.t('toast.category_delete_failed'), 'error');
        }
    } finally {
        elements.deleteModalConfirm.disabled = false;
    }
}

function openTotpModal(accountId, mode) {
    appState.editingTotp = accountId;
    appState.totpModalMode = mode || 'manual';

    cleanupTotpModal();

    if (accountId) {
        const account = appState.totpAccounts.find(function(a) {
            return a.id === accountId;
        });
        if (account) {
            elements.totpModalTitle.textContent = i18n.t('authenticator.edit_account');
            elements.totpName.value = account.name || '';
            elements.totpIssuer.value = account.issuer || '';
            elements.totpSecret.value = account.secret || '';
            elements.totpDigits.value = account.digits || '6';
            elements.totpPeriod.value = account.period || '30';
        }
    } else {
        if (mode === 'qr') {
            elements.totpModalTitle.innerHTML = '<i class="fas fa-qrcode"></i> <span>' + i18n.t('authenticator.scan_qr') + '</span>';
            showQrScanInterface();
        } else {
            elements.totpModalTitle.innerHTML = '<i class="fas fa-keyboard"></i> <span>' + i18n.t('authenticator.manual_entry') + '</span>';
            showManualEntryInterface();
        }
        elements.totpForm.reset();
    }

    elements.totpModal.style.display = 'block';

    if (mode === 'manual' || accountId) {
        setTimeout(function() {
            if (elements.totpName) elements.totpName.focus();
        }, 100);
    }
}

function cleanupTotpModal() {
    if (appState.qrScanningTimeout) {
        clearTimeout(appState.qrScanningTimeout);
        appState.qrScanningTimeout = null;
    }

    stopDesktopCapture();

    const qrScanSection = document.getElementById('qr-scan-section');
    const switchToQrSection = document.getElementById('switch-to-qr-section');

    if (qrScanSection) qrScanSection.remove();
    if (switchToQrSection) switchToQrSection.remove();

    elements.totpForm.style.display = 'block';
}

function showQrScanInterface() {
    cleanupTotpModal();

    const modalBody = elements.totpModal.querySelector('.modal-body');

    const qrScanSection = document.createElement('div');
    qrScanSection.id = 'qr-scan-section';
    qrScanSection.innerHTML =
        '<div style="text-align: center; margin-bottom: 1.5rem;">' +
            '<div id="qr-capture-container" style="background: var(--bg-primary); border: 2px dashed var(--border-primary); border-radius: var(--radius-lg); padding: 2rem; margin-bottom: 1rem; position: relative; min-height: 300px; display: flex; flex-direction: column; align-items: center; justify-content: center;">' +
                '<div id="qr-placeholder" style="display: flex; flex-direction: column; align-items: center; justify-content: center;">' +
                    '<i class="fas fa-desktop" style="font-size: 3rem; color: var(--text-muted); margin-bottom: 1rem;"></i>' +
                    '<p style="color: var(--text-secondary); margin-bottom: 1rem; text-align: center;">' + i18n.t('authenticator.desktop_scan_description') + '</p>' +
                    '<button type="button" class="btn btn-sm btn-outline" id="start-screen-capture-btn">' +
                        '<i class="fas fa-camera"></i>' +
                        '<span>' + i18n.t('authenticator.start_desktop_scan') + '</span>' +
                    '</button>' +
                '</div>' +
                '<div id="qr-scanning" style="display: none; flex-direction: column; align-items: center; justify-content: center;">' +
                    '<canvas id="screen-capture-canvas" style="max-width: 100%; max-height: 200px; border: 2px solid var(--primary-color); border-radius: var(--radius-md); margin-bottom: 1rem;"></canvas>' +
                    '<div style="width: 150px; height: 150px; border: 3px solid var(--primary-color); border-radius: var(--radius-md); position: relative; margin-bottom: 1rem; display: flex; align-items: center; justify-content: center; animation: pulse 2s infinite;">' +
                        '<i class="fas fa-qrcode" style="font-size: 2rem; color: var(--primary-color);"></i>' +
                        '<div style="position: absolute; top: -2px; left: -2px; right: -2px; height: 4px; background: var(--primary-color); animation: scan 2s linear infinite;"></div>' +
                    '</div>' +
                    '<p style="color: var(--primary-color); margin-bottom: 1rem; font-weight: 600;">' + i18n.t('authenticator.scanning_desktop') + '</p>' +
                    '<button type="button" class="btn btn-outline btn-sm" id="stop-capture-btn">' +
                        '<i class="fas fa-stop"></i>' +
                        '<span>' + i18n.t('authenticator.stop_scanning') + '</span>' +
                    '</button>' +
                '</div>' +
                '<div id="qr-success" style="display: none; flex-direction: column; align-items: center; justify-content: center;">' +
                    '<i class="fas fa-check-circle" style="font-size: 3rem; color: var(--success-color); margin-bottom: 1rem;"></i>' +
                    '<p style="color: var(--success-color); font-weight: 600; margin-bottom: 1rem;">' + i18n.t('authenticator.qr_detected') + '</p>' +
                    '<p style="color: var(--text-secondary); font-size: 0.85rem;">' + i18n.t('authenticator.account_loaded') + '</p>' +
                '</div>' +
            '</div>' +
            '<p style="color: var(--text-muted); font-size: 0.85rem;">' +
                i18n.t('authenticator.or_manual') +
                '<button type="button" class="btn btn-sm btn-outline" id="switch-to-manual">' +
                    '<i class="fas fa-keyboard"></i>' +
                    '<span>' + i18n.t('authenticator.enter_manually') + '</span>' +
                '</button>' +
            '</p>' +
        '</div>' +

        '<style>' +
            '@keyframes pulse {' +
                '0% { box-shadow: 0 0 0 0 rgba(0, 212, 255, 0.4); }' +
                '70% { box-shadow: 0 0 0 20px rgba(0, 212, 255, 0); }' +
                '100% { box-shadow: 0 0 0 0 rgba(0, 212, 255, 0); }' +
            '}' +

            '@keyframes scan {' +
                '0% { top: -2px; }' +
                '50% { top: calc(100% - 2px); }' +
                '100% { top: -2px; }' +
            '}' +
        '</style>';

    modalBody.insertBefore(qrScanSection, elements.totpForm);
    elements.totpForm.style.display = 'none';

    const startCaptureBtn = document.getElementById('start-screen-capture-btn');
    const stopCaptureBtn = document.getElementById('stop-capture-btn');
    const switchToManualBtn = document.getElementById('switch-to-manual');

    if (startCaptureBtn) {
        startCaptureBtn.addEventListener('click', startDesktopQrScanning);
    }

    if (stopCaptureBtn) {
        stopCaptureBtn.addEventListener('click', stopDesktopCapture);
    }

    if (switchToManualBtn) {
        switchToManualBtn.addEventListener('click', function() {
            appState.totpModalMode = 'manual';
            showManualEntryInterface();
            elements.totpModalTitle.innerHTML = '<i class="fas fa-keyboard"></i> <span>' + i18n.t('authenticator.manual_entry') + '</span>';
        });
    }
}

async function startDesktopQrScanning() {
    console.log('Starting desktop QR scanning...');

    const qrPlaceholder = document.getElementById('qr-placeholder');
    const qrScanning = document.getElementById('qr-scanning');
    const canvas = document.getElementById('screen-capture-canvas');
    const ctx = canvas.getContext('2d');

    if (!qrPlaceholder || !qrScanning || !canvas) {
        console.error('QR scanning elements not found');
        return;
    }

    qrPlaceholder.style.display = 'none';
    qrScanning.style.display = 'flex';

    try {
        const sources = await ipcRenderer.invoke('get-desktop-sources');
        if (!sources.success || !sources.sources.length) {
            throw new Error(i18n.t('toast.desktop_scan_sources_unavailable'));
        }

        const primaryScreen = sources.sources.find(function(s) {
            return s.name.includes('Entire Screen') || s.name.includes('Screen 1');
        }) || sources.sources[0];

        startScreenCapture(primaryScreen.id, canvas, ctx);
        showToast(i18n.t('toast.desktop_scan_started'), 'info');
    } catch (error) {
        console.error('Error starting desktop capture:', error);
        showToast(i18n.t('toast.desktop_scan_failed'), 'error');
        stopDesktopCapture();
    }
}

async function startScreenCapture(sourceId, canvas, ctx) {
    appState.screenCaptureInterval = setInterval(async function() {
        try {
            const result = await ipcRenderer.invoke('capture-screen', sourceId);
            if (result.success) {
                const img = new Image();
                img.onload = function() {
                    canvas.width = Math.min(img.width, 600);
                    canvas.height = (img.height * canvas.width) / img.width;
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

                    detectQRCodeFromCanvas(canvas);
                };
                img.src = result.dataUrl;
            }
        } catch (error) {
            console.error('Error capturing screen:', error);
        }
    }, 1000);
}

function detectQRCodeFromCanvas(canvas) {
    try {
        const imageData = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);

        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
            console.log('QR Code detected:', code.data);
            handleQRCodeDetected(code.data);
            return;
        }

        const qrCodeUrls = findQRCodePatterns(canvas);
        if (qrCodeUrls.length > 0) {
            console.log('QR pattern detected:', qrCodeUrls[0]);
            handleQRCodeDetected(qrCodeUrls[0]);
        }
    } catch (error) {
        console.error('Error detecting QR code:', error);
    }
}

function findQRCodePatterns(canvas) {
    const patterns = [];
    const ctx = canvas.getContext('2d');

    const samplePoints = [
        { x: canvas.width * 0.25, y: canvas.height * 0.25 },
        { x: canvas.width * 0.5, y: canvas.height * 0.5 },
        { x: canvas.width * 0.75, y: canvas.height * 0.75 }
    ];

    for (const point of samplePoints) {
        const imageData = ctx.getImageData(point.x - 50, point.y - 50, 100, 100);
        const hasQRPattern = detectQRPattern(imageData);
        if (hasQRPattern) {
            patterns.push('qr-pattern-detected');
        }
    }

    return patterns;
}

function detectQRPattern(imageData) {
    let blackPixels = 0;
    let whitePixels = 0;

    for (let i = 0; i < imageData.data.length; i += 4) {
        const r = imageData.data[i];
        const g = imageData.data[i + 1];
        const b = imageData.data[i + 2];
        const brightness = (r + g + b) / 3;

        if (brightness < 128) {
            blackPixels++;
        } else {
            whitePixels++;
        }
    }

    const ratio = blackPixels / (blackPixels + whitePixels);
    return ratio > 0.3 && ratio < 0.7;
}

function handleQRCodeDetected(qrData) {
    try {
        const parsed = parseTotpUrl(qrData);
        if (parsed) {
            stopDesktopCapture();
            showQRSuccess();

            setTimeout(function() {
                if (elements.totpName) elements.totpName.value = parsed.label || '';
                if (elements.totpIssuer) elements.totpIssuer.value = parsed.issuer || '';
                if (elements.totpSecret) elements.totpSecret.value = parsed.secret || '';
                if (elements.totpDigits) elements.totpDigits.value = parsed.digits || '6';
                if (elements.totpPeriod) elements.totpPeriod.value = parsed.period || '30';

                showManualEntryInterface();
                elements.totpModalTitle.innerHTML = '<i class="fas fa-check-circle" style="color: var(--success-color);"></i> <span>' + i18n.t('authenticator.qr_scanned') + '</span>';
                showToast(i18n.t('toast.qr_scanned_success'), 'success');

                setTimeout(function() {
                    if (elements.totpName) {
                        elements.totpName.focus();
                        elements.totpName.select();
                    }
                }, 100);
            }, 1500);
        } else {
            console.log('Invalid QR code format');
            showToast(i18n.t('toast.invalid_qr_format'), 'error');
        }
    } catch (error) {
        console.error('Error handling QR code:', error);
    }
}

function showQRSuccess() {
    const qrScanning = document.getElementById('qr-scanning');
    const qrSuccess = document.getElementById('qr-success');

    if (qrScanning) qrScanning.style.display = 'none';
    if (qrSuccess) qrSuccess.style.display = 'flex';
}

function stopDesktopCapture() {
    console.log('Stopping desktop capture...');

    if (appState.screenCaptureInterval) {
        clearInterval(appState.screenCaptureInterval);
        appState.screenCaptureInterval = null;
        showToast(i18n.t('toast.desktop_scan_stopped'), 'info');
    }

    const qrPlaceholder = document.getElementById('qr-placeholder');
    const qrScanning = document.getElementById('qr-scanning');
    const qrSuccess = document.getElementById('qr-success');

    if (qrPlaceholder && qrScanning) {
        qrScanning.style.display = 'none';
        qrPlaceholder.style.display = 'flex';
    }

    if (qrSuccess) {
        qrSuccess.style.display = 'none';
    }
}

function parseTotpUrl(url) {
    try {
        console.log('Parsing TOTP URL:', url);

        const urlObj = new URL(url);

        if (urlObj.protocol !== 'otpauth:' || urlObj.host !== 'totp') {
            throw new Error(i18n.t('errors.invalid_totp_format'));
        }

        const params = urlObj.searchParams;
        const pathParts = urlObj.pathname.substring(1).split(':');

        const result = {
            label: pathParts.length > 1 ? decodeURIComponent(pathParts[1]) : decodeURIComponent(pathParts[0]),
            issuer: params.get('issuer') || (pathParts.length > 1 ? decodeURIComponent(pathParts[0]) : ''),
            secret: params.get('secret') || '',
            digits: params.get('digits') || '6',
            period: params.get('period') || '30'
        };

        console.log('Parsed result:', result);
        return result;
    } catch (error) {
        console.error('Error parsing TOTP URL:', error);
        return null;
    }
}

function showManualEntryInterface() {
    cleanupTotpModal();

    elements.totpForm.style.display = 'block';

    if (!appState.editingTotp) {
        const switchToQrSection = document.createElement('div');
        switchToQrSection.id = 'switch-to-qr-section';
        switchToQrSection.innerHTML =
            '<p style="color: var(--text-muted); font-size: 0.85rem; text-align: center; margin-top: 1rem;">' +
                i18n.t('authenticator.have_qr') +
                '<button type="button" class="btn btn-sm btn-outline" id="switch-to-qr">' +
                    '<i class="fas fa-qrcode"></i>' +
                    '<span>' + i18n.t('authenticator.scan_qr') + '</span>' +
                '</button>' +
            '</p>';

        elements.totpForm.appendChild(switchToQrSection);

        const switchToQrBtn = document.getElementById('switch-to-qr');
        if (switchToQrBtn) {
            switchToQrBtn.addEventListener('click', function() {
                appState.totpModalMode = 'qr';
                showQrScanInterface();
                elements.totpModalTitle.innerHTML = '<i class="fas fa-qrcode"></i> <span>' + i18n.t('authenticator.scan_qr') + '</span>';
            });
        }
    }
}

function closeTotpModal() {
    elements.totpModal.style.display = 'none';
    appState.editingTotp = null;
    appState.totpModalMode = 'manual';

    cleanupTotpModal();
    elements.totpForm.reset();
}

async function saveTotp() {
    const name = elements.totpName ? elements.totpName.value.trim() : '';
    const issuer = elements.totpIssuer ? elements.totpIssuer.value.trim() : '';
    const secret = elements.totpSecret ? elements.totpSecret.value.trim().replace(/\s/g, '') : '';
    const digits = parseInt(elements.totpDigits ? elements.totpDigits.value : '6') || 6;
    const period = parseInt(elements.totpPeriod ? elements.totpPeriod.value : '30') || 30;

    if (!name || !secret) {
        showToast(i18n.t('common.name_secret_required'), 'error');
        return;
    }

    if (!isValidBase32(secret)) {
        showToast(i18n.t('toast.invalid_secret_key'), 'error');
        return;
    }

    const totpEntry = {
        id: appState.editingTotp,
        name: name,
        issuer: issuer,
        secret: secret,
        digits: digits,
        period: period
    };

    try {
        elements.totpModalSave.disabled = true;
        const result = await ipcRenderer.invoke('save-totp-entry', totpEntry);

        if (result.success) {
            showToast(i18n.t('toast.account_saved'), 'success');
            closeTotpModal();
            await loadTotpAccounts();
        } else {
            showToast(result.error || i18n.t('toast.save_account_failed'), 'error');
        }
    } catch (error) {
        console.error('Error saving TOTP account:', error);
        showToast(i18n.t('toast.save_account_failed'), 'error');
    } finally {
        elements.totpModalSave.disabled = false;
    }
}

function openChangePasswordModal() {
    elements.changePasswordModal.style.display = 'block';
    setTimeout(function() {
        if (elements.currentMasterPassword) elements.currentMasterPassword.focus();
    }, 100);
}

function closeChangePasswordModal() {
    elements.changePasswordModal.style.display = 'none';
    elements.changePasswordForm.reset();
}

async function changeMasterPassword() {
    const currentPassword = elements.currentMasterPassword ? elements.currentMasterPassword.value : '';
    const newPassword = elements.newMasterPassword ? elements.newMasterPassword.value : '';
    const confirmPassword = elements.confirmNewMasterPassword ? elements.confirmNewMasterPassword.value : '';

    if (!currentPassword || !newPassword || !confirmPassword) {
        showToast(i18n.t('common.fill_all_fields'), 'error');
        return;
    }

    if (newPassword !== confirmPassword) {
        showToast(i18n.t('toast.passwords_dont_match'), 'error');
        return;
    }

    const strength = zxcvbn(newPassword);
    if (strength.score < 3) {
        showToast(i18n.t('toast.weak_password'), 'error');
        return;
    }

    try {
        elements.changePasswordModalSave.disabled = true;
        const result = await ipcRenderer.invoke('change-master-password', currentPassword, newPassword);

        if (result.success) {
            showToast(i18n.t('toast.master_password_changed'), 'success');
            closeChangePasswordModal();
        } else {
            showToast(result.error || i18n.t('toast.change_password_failed'), 'error');
        }
    } catch (error) {
        console.error('Error changing master password:', error);
        showToast(i18n.t('toast.change_password_failed'), 'error');
    } finally {
        elements.changePasswordModalSave.disabled = false;
    }
}

/**
 * Enhanced Export/Import Functions with Format Selection
 */

function openExportModal() {
    const modal = document.getElementById('import-export-modal');
    const title = document.getElementById('import-export-title');
    const exportSection = document.getElementById('export-section');
    const importSection = document.getElementById('import-section');
    const actionButton = document.getElementById('import-export-action');

    title.textContent = i18n.t('import_export.title');
    exportSection.style.display = 'block';
    importSection.style.display = 'none';
    actionButton.textContent = i18n.t('common.export');
    actionButton.onclick = performExport;

    const exportFormat = document.getElementById('export-format');
    exportFormat.onchange = function() {
        const passwordGroup = document.getElementById('export-password-group');
        passwordGroup.style.display = this.value === 'securevault' ? 'block' : 'none';
    };

    modal.style.display = 'flex';
}

function openImportModal() {
    const modal = document.getElementById('import-export-modal');
    const title = document.getElementById('import-export-title');
    const exportSection = document.getElementById('export-section');
    const importSection = document.getElementById('import-section');
    const actionButton = document.getElementById('import-export-action');

    title.textContent = i18n.t('import_export.title');
    exportSection.style.display = 'none';
    importSection.style.display = 'block';
    actionButton.textContent = i18n.t('common.import');
    actionButton.onclick = performImport;

    const importFormat = document.getElementById('import-format');
    importFormat.onchange = function() {
        const passwordGroup = document.getElementById('import-password-group');
        passwordGroup.style.display = this.value === 'securevault' ? 'block' : 'none';
    };

    const importFile = document.getElementById('import-file');
    importFile.onchange = function() {
        const filename = document.getElementById('import-filename');
        filename.textContent = this.files.length > 0 ? this.files[0].name : i18n.t('common.no_file_selected');
    };

    modal.style.display = 'flex';
}

function closeImportExportModal() {
    document.getElementById('import-export-modal').style.display = 'none';
}

async function performExport() {
    try {
        const format = document.getElementById('export-format').value;
        const password = document.getElementById('export-password').value;

        const result = await ipcRenderer.invoke('export-vault', format, password || null);
        if (result.success && !result.canceled) {
            showToast(i18n.t('toast.exported_entries', { count: result.count || 0, format: format }), 'success');
            closeImportExportModal();
        }
    } catch (error) {
        console.error('Error exporting vault:', error);
        showToast(i18n.t('toast.export_failed') + ': ' + error.message, 'error');
    }
}

async function performImport() {
    try {
        const file = document.getElementById('import-file').files[0];
        if (!file) {
            showToast(i18n.t('toast.import_no_file'), 'error');
            return;
        }

        const password = document.getElementById('import-password').value;
        const format = document.getElementById('import-format').value;
        
        const fileContent = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });

        const result = await ipcRenderer.invoke('import-from-content', {
            filename: file.name,
            content: fileContent,
            format: format === 'auto' ? null : format,
            password: password || null
        });

        if (result.success) {
            let message = i18n.t('toast.imported_entries', { count: result.imported || 0, format: result.format });
            if (result.passwordCount && result.totpCount) {
                message += ` (${result.passwordCount} passwords, ${result.totpCount} TOTP accounts)`;
            } else if (result.passwordCount) {
                message += ` (${result.passwordCount} passwords)`;
            } else if (result.totpCount) {
                message += ` (${result.totpCount} TOTP accounts)`;
            }
            
            showToast(message, 'success');
            await loadPasswords();
            await loadTotpAccounts();
            closeImportExportModal();
        } else {
            showToast(i18n.t('toast.import_failed') + ': ' + (result.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error importing vault:', error);
        showToast(i18n.t('toast.import_failed') + ': ' + error.message, 'error');
    }
}

async function exportVault() {
    openExportModal();
}

async function importVault() {
    openImportModal();
}

/**
 * Password Security Audit Functions
 */

async function openAuditModal() {
    const modal = document.getElementById('audit-modal');
    modal.style.display = 'flex';

    try {
        const result = await ipcRenderer.invoke('audit-passwords');
        if (result.success) {
            displayAuditResults(result.audit);
        } else {
            showToast(i18n.t('toast.audit_failed') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(i18n.t('toast.audit_failed') + ': ' + error.message, 'error');
    }
}

function closeAuditModal() {
    document.getElementById('audit-modal').style.display = 'none';
}

function displayAuditResults(audit) {
    document.getElementById('total-passwords').textContent = audit.total;
    document.getElementById('weak-passwords').textContent = audit.weak;
    document.getElementById('reused-passwords').textContent = audit.reused;
    document.getElementById('old-passwords').textContent = audit.old;

    const detailsContainer = document.getElementById('audit-details');
    detailsContainer.innerHTML = '';

    if (audit.details.length === 0) {
        detailsContainer.innerHTML = '<div class="audit-success"><i class="fas fa-check-circle"></i> ' + i18n.t('audit.no_issues') + '</div>';
        return;
    }

    audit.details.forEach(function(detail) {
        const issueItem = document.createElement('div');
        issueItem.className = 'audit-issue';

        const issueText = detail.issues.map(function(issue) {
            switch(issue) {
            case 'too_short': return i18n.t('audit.password_too_short');
            case 'weak': return i18n.t('audit.weak_password');
            case 'reused': return i18n.t('audit.reused_password');
            case 'old': return i18n.t('audit.old_password');
            default: return issue;
            }
        }).join(', ');

        issueItem.innerHTML = `
            <div class="issue-header">
                <span class="issue-name">${escapeHtml(detail.name)}</span>
                <span class="issue-badges">
                    ${detail.issues.map(issue => `<span class="badge badge-${issue === 'reused' ? 'warning' : 'danger'}">${issue.replace('_', ' ')}</span>`).join('')}
                </span>
            </div>
        `;

        detailsContainer.appendChild(issueItem);
    });
}

/**
 * Category Management Functions
 */

async function openCategoryModal() {
    const modal = document.getElementById('category-modal');
    modal.style.display = 'flex';
    await loadCategories();
}

function closeCategoryModal() {
    document.getElementById('category-modal').style.display = 'none';
}

async function loadCategories() {
    try {
        const result = await ipcRenderer.invoke('get-categories');
        if (result.success) {
            displayCategories(result.categories);
        }
    } catch (error) {
        console.error('Error loading categories:', error);
        showToast(i18n.t('toast.category_load_failed'), 'error');
    }
}

function displayCategories(categories) {
    const container = document.getElementById('categories-list');
    container.innerHTML = '';

    categories.forEach(function(category) {
        const categoryItem = document.createElement('div');
        categoryItem.className = 'category-item';
        categoryItem.innerHTML = `
            <div class="category-info">
                <div class="category-color" style="background-color: ${category.color}"></div>
                <span class="category-icon">${getCategoryIconFromType(category.icon)}</span>
                <span class="category-name">${escapeHtml(category.name)}</span>
            </div>
            <div class="category-actions">
                <button class="btn btn-sm btn-outline btn-danger" onclick="deleteCategory('${category.id}', '${escapeHtml(category.name)}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        container.appendChild(categoryItem);
    });
}

function showAddCategoryForm() {
    const form = document.getElementById('add-category-form');
    form.style.display = 'block';
    document.getElementById('category-name').focus();
}

function cancelAddCategory() {
    const form = document.getElementById('add-category-form');
    form.style.display = 'none';
    document.getElementById('category-name').value = '';
    document.getElementById('category-color').value = '#6366f1';
    document.getElementById('category-icon').value = 'folder';
}

async function saveCategory() {
    const name = document.getElementById('category-name').value.trim();
    const color = document.getElementById('category-color').value;
    const icon = document.getElementById('category-icon').value;

    if (!name) {
        showToast(i18n.t('toast.category_name_required'), 'error');
        return;
    }

    try {
        const category = { name, color, icon };
        const result = await ipcRenderer.invoke('save-category', category);

        if (result.success) {
            showToast(i18n.t('toast.category_saved'), 'success');
            cancelAddCategory();
            await loadCategories();
            await loadPasswords();
            await populateCategoryDropdowns();
        } else {
            showToast(i18n.t('toast.category_save_failed') + ': ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error saving category:', error);
        showToast(i18n.t('toast.category_save_failed'), 'error');
    }
}

function deleteCategory(categoryId, categoryName) {
    openDeleteModal('category', categoryId, categoryName);
}

window.copyUsername = async function(passwordId) {
    const password = appState.passwords.find(function(p) {
        return p.id === passwordId;
    });
    if (password && password.username) {
        await copyToClipboard(password.username);
        showToast(i18n.t('toast.username_copied'), 'success');
    }
};

window.copyPassword = async function(passwordId) {
    const password = appState.passwords.find(function(p) {
        return p.id === passwordId;
    });
    if (password && password.password) {
        await copyToClipboard(password.password);
        showToast(i18n.t('toast.password_copied'), 'success');
    }
};

window.visitWebsite = function(passwordId) {
    const password = appState.passwords.find(function(p) {
        return p.id === passwordId;
    });
    if (password && password.url) {
        require('electron').shell.openExternal(password.url);
    }
};

window.editPassword = function(passwordId) {
    openPasswordModal(passwordId);
};

window.deletePassword = function(passwordId) {
    const password = appState.passwords.find(function(p) {
        return p.id === passwordId;
    });
    if (password) {
        openDeleteModal('password', passwordId, password.name);
    }
};

window.copyTotpCode = async function(accountId) {
    const account = appState.totpAccounts.find(function(a) {
        return a.id === accountId;
    });
    if (account) {
        const code = generateTotpCode(account);
        await copyToClipboard(code);
        showToast(i18n.t('toast.code_copied'), 'success');
    }
};

window.editTotp = function(accountId) {
    openTotpModal(accountId, 'manual');
};

window.deleteTotp = function(accountId) {
    const account = appState.totpAccounts.find(function(a) {
        return a.id === accountId;
    });
    if (account) {
        openDeleteModal('account', accountId, account.name);
    }
};

function generateTotpCode(account) {
    try {
        return speakeasy.totp({
            secret: account.secret,
            encoding: 'base32',
            digits: account.digits || 6,
            step: account.period || 30
        });
    } catch (error) {
        console.error('Error generating TOTP code:', error);
        return '------';
    }
}

function getTotpTimeRemaining(period) {
    period = period || 30;
    const now = Math.floor(Date.now() / 1000);
    return period - (now % period);
}

/**
 * Advanced Search Functions
 */

async function openSearchModal() {
    const modal = document.getElementById('search-modal');
    modal.style.display = 'flex';

    document.getElementById('search-name').value = '';
    document.getElementById('search-username').value = '';
    document.getElementById('search-url').value = '';
    document.getElementById('search-category').value = '';
    document.getElementById('search-tags').value = '';
    document.getElementById('search-weak-only').checked = false;
    document.getElementById('search-old-only').checked = false;

    await loadCategoriesForSearch();
}

function closeSearchModal() {
    document.getElementById('search-modal').style.display = 'none';
    document.getElementById('search-results').innerHTML = '';
}

async function loadCategoriesForSearch() {
    try {
        const result = await ipcRenderer.invoke('get-categories');
        if (result.success) {
            const select = document.getElementById('search-category');
            select.innerHTML = '<option value="">' + i18n.t('categories.all_categories') + '</option>';

            result.categories.forEach(function(category) {
                const option = document.createElement('option');
                option.value = category.name;
                option.textContent = category.name;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading categories for search:', error);
    }
}

async function populateCategoryDropdowns() {
    try {
        const filterSelect = document.getElementById('password-category-filter');
        const passwordSelect = document.getElementById('password-category');
        
        const result = await ipcRenderer.invoke('get-categories');
        
        if (result.success && result.categories) {
            if (filterSelect) {
                filterSelect.innerHTML = '<option value="">' + i18n.t('passwords.all_categories') + '</option>';
                
                result.categories.forEach(function(category) {
                    const option = document.createElement('option');
                    option.value = category.name;
                    option.textContent = category.name;
                    option.style.color = category.color || '#6366f1';
                    filterSelect.appendChild(option);
                });
            }

            if (passwordSelect) {
                passwordSelect.innerHTML = '';
                
                result.categories.forEach(function(category) {
                    const option = document.createElement('option');
                    option.value = category.name;
                    option.textContent = category.name;
                    option.style.color = category.color || '#6366f1';
                    passwordSelect.appendChild(option);
                });
            }
        }
    } catch (error) {
        console.error('Error loading categories:', error);
    }
}

async function performAdvancedSearch() {
    const criteria = {
        name: document.getElementById('search-name').value,
        username: document.getElementById('search-username').value,
        url: document.getElementById('search-url').value,
        category: document.getElementById('search-category').value,
        tags: document.getElementById('search-tags').value.split(',').map(function(tag) { return tag.trim(); }).filter(Boolean),
        weakOnly: document.getElementById('search-weak-only').checked,
        oldOnly: document.getElementById('search-old-only').checked
    };

    try {
        const result = await ipcRenderer.invoke('search-passwords', criteria);
        if (result.success) {
            displaySearchResults(result.passwords);
        } else {
            showToast(i18n.t('toast.search_failed') + ': ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error performing advanced search:', error);
        showToast(i18n.t('toast.search_failed') + ': ' + error.message, 'error');
    }
}

function displaySearchResults(passwords) {
    const container = document.getElementById('search-results');
    container.innerHTML = '';

    if (passwords.length === 0) {
        container.innerHTML = '<div class="no-results"><i class="fas fa-search"></i> ' + i18n.t('search.no_results') + '</div>';
        return;
    }

    const plural = passwords.length === 1 ? '' : 's';
    const headerText = i18n.t('search.found_results').replace('{count}', passwords.length).replace('{plural}', plural);
    container.innerHTML = `<div class="search-header">${headerText}</div>`;

    passwords.forEach(function(password) {
        const passwordItem = document.createElement('div');
        passwordItem.className = 'search-result-item';
        passwordItem.innerHTML = `
            <div class="password-info">
                <div class="password-name">${escapeHtml(password.name)}</div>
                <div class="password-details">
                    <span class="password-username">${escapeHtml(password.username)}</span>
                    ${password.url ? `<span class="password-url">${escapeHtml(password.url)}</span>` : ''}
                </div>
                <div class="password-meta">
                    <span class="password-category">${escapeHtml(password.category)}</span>
                    ${password.tags && password.tags.length > 0 ? `<span class="password-tags">${password.tags.map(function(tag) { return escapeHtml(tag); }).join(', ')}</span>` : ''}
                </div>
            </div>
            <div class="password-actions">
                <button class="btn btn-sm btn-outline" onclick="copyUsername('${password.id}')">
                    <i class="fas fa-user"></i>
                </button>
                <button class="btn btn-sm btn-outline" onclick="copyPassword('${password.id}')">
                    <i class="fas fa-key"></i>
                </button>
                ${password.url ? `<button class="btn btn-sm btn-outline" onclick="visitWebsite('${password.id}')">
                    <i class="fas fa-external-link-alt"></i>
                </button>` : ''}
                <button class="btn btn-sm btn-outline" onclick="editPassword('${password.id}'); closeSearchModal();">
                    <i class="fas fa-edit"></i>
                </button>
            </div>
        `;
        container.appendChild(passwordItem);
    });
}

function clearSearchFilters() {
    document.getElementById('search-name').value = '';
    document.getElementById('search-username').value = '';
    document.getElementById('search-url').value = '';
    document.getElementById('search-category').value = '';
    document.getElementById('search-tags').value = '';
    document.getElementById('search-weak-only').checked = false;
    document.getElementById('search-old-only').checked = false;
    document.getElementById('search-results').innerHTML = '';
}

/**
 * Settings Modal Functions
 */

let settingsData = {
    startupEnabled: false,
    shortcuts: {
        quickAccess: i18n.t('shortcuts.quick_access'),
        autoLock: i18n.t('shortcuts.auto_lock')
    },
    clipboardTimeout: 30,
    notificationsEnabled: true,
    autoLockTimeout: 1800,
    closeToTray: true
};


async function loadSettings() {
    try {
        const startupResult = await ipcRenderer.invoke('get-startup-status');
        if (startupResult.success) {
            document.getElementById('startup-enabled').checked = startupResult.enabled;
            settingsData.startupEnabled = startupResult.enabled;
        }

        const settingsResult = await ipcRenderer.invoke('get-app-settings');
        if (settingsResult.success && settingsResult.settings) {
            const settings = settingsResult.settings;

            document.getElementById('clipboard-timeout').value = settings.clipboardTimeout || 30;
            document.getElementById('notifications-enabled').checked = settings.notificationsEnabled !== false;
            document.getElementById('auto-lock-timeout').value = settings.autoLockTimeout || 1800;
            document.getElementById('close-to-tray').checked = settings.closeToTray !== false;

            if (settings.shortcuts) {
                document.getElementById('quick-access-shortcut').value = settings.shortcuts.quickAccess || '';
                document.getElementById('auto-lock-shortcut').value = settings.shortcuts.autoLock || '';
            }

            settingsData = { ...settingsData, ...settings };
        }
    } catch (error) {
        console.error('Error loading settings:', error);
        showToast(i18n.t('toast.settings_load_failed'), 'error');
    }
}

async function saveSettings() {
    try {
        const newSettings = {
            clipboardTimeout: parseInt(document.getElementById('clipboard-timeout').value),
            notificationsEnabled: document.getElementById('notifications-enabled').checked,
            autoLockTimeout: parseInt(document.getElementById('auto-lock-timeout').value),
            closeToTray: document.getElementById('close-to-tray').checked,
            shortcuts: {
                quickAccess: document.getElementById('quick-access-shortcut').value,
                autoLock: document.getElementById('auto-lock-shortcut').value
            }
        };

        const startupEnabled = document.getElementById('startup-enabled').checked;
        if (startupEnabled !== settingsData.startupEnabled) {
            const startupResult = await ipcRenderer.invoke('set-startup', startupEnabled);
            if (!startupResult.success) {
                showToast(i18n.t('toast.startup_setting_failed') + ': ' + startupResult.error, 'error');
                return;
            }
        }

        const result = await ipcRenderer.invoke('save-app-settings', newSettings);
        if (result.success) {
            settingsData = { ...settingsData, ...newSettings };
            showToast(i18n.t('toast.settings_saved'), 'success');
        } else {
            showToast(i18n.t('toast.settings_save_failed') + ': ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        showToast(i18n.t('toast.settings_save_failed'), 'error');
    }
}

function recordShortcut(shortcutType) {
    const input = document.getElementById(shortcutType + '-shortcut');
    const button = input.nextElementSibling;

    button.textContent = i18n.t('common.press_keys');
    button.disabled = true;

    const handleKeyDown = function(event) {
        event.preventDefault();

        const keys = [];
        if (event.ctrlKey) keys.push(i18n.t('keys.ctrl'));
        if (event.altKey) keys.push(i18n.t('keys.alt'));
        if (event.shiftKey) keys.push(i18n.t('keys.shift'));
        if (event.metaKey) keys.push(i18n.t('keys.meta'));

        if (event.key && !['Control', 'Alt', 'Shift', 'Meta'].includes(event.key)) {
            keys.push(event.key.toUpperCase());
        }

        if (keys.length >= 2) {
            const shortcut = keys.join('+');
            input.value = shortcut;

            document.removeEventListener('keydown', handleKeyDown);
            button.textContent = i18n.t('common.set');
            button.disabled = false;
        }
    };

    document.addEventListener('keydown', handleKeyDown);

    setTimeout(function() {
        document.removeEventListener('keydown', handleKeyDown);
        button.textContent = i18n.t('common.set');
        button.disabled = false;
    }, 10000);
}

async function exportBackup() {
    try {
        const result = await ipcRenderer.invoke('export-secure-backup');
        if (result.success) {
            showToast(i18n.t('toast.backup_exported'), 'success');
        } else {
            showToast(i18n.t('toast.export_failed') + ': ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error exporting backup:', error);
        showToast(i18n.t('toast.export_failed') + ': ' + error.message, 'error');
    }
}

function startTotpCountdown() {
    setInterval(function() {
        if (!appState.isUnlocked) return;

        document.querySelectorAll('.totp-code').forEach(function(codeElement) {
            const accountId = codeElement.dataset.accountId;
            const account = appState.totpAccounts.find(function(a) {
                return a.id === accountId;
            });
            if (account) {
                const newCode = generateTotpCode(account);
                codeElement.textContent = newCode;
            }
        });

        document.querySelectorAll('.totp-countdown').forEach(function(countdown) {
            const period = parseInt(countdown.dataset.period) || 30;
            const timeRemaining = getTotpTimeRemaining(period);
            const countdownText = countdown.querySelector('.countdown-text');
            const circle = countdown.querySelector('circle');

            if (countdownText) {
                countdownText.textContent = timeRemaining + 's';
            }

            if (circle) {
                const circumference = 2 * Math.PI * 8;
                const offset = circumference * (1 - timeRemaining / period);
                circle.style.strokeDashoffset = offset;
            }
        });
    }, 1000);
}

function generatePassword() {
    const length = 16;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';

    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    elements.passwordPassword.value = password;
    updatePasswordStrength(elements.passwordPassword, elements.passwordStrength);
}

function togglePasswordVisibility(input, button) {
    if (input.type === 'password') {
        input.type = 'text';
        button.querySelector('i').className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        button.querySelector('i').className = 'fas fa-eye';
    }
}

function updatePasswordStrength(input, strengthElement) {
    if (!input || !strengthElement) return;

    const password = input.value;
    if (!password) {
        strengthElement.innerHTML = '';
        return;
    }

    const result = zxcvbn(password);
    const strengthLevels = [
        { text: i18n.t('passwords.strength_very_weak'), class: 'very-weak' },
        { text: i18n.t('passwords.strength_weak'), class: 'weak' },
        { text: i18n.t('passwords.strength_fair'), class: 'fair' },
        { text: i18n.t('passwords.strength_good'), class: 'good' },
        { text: i18n.t('passwords.strength_strong'), class: 'strong' }
    ];

    const strength = strengthLevels[result.score];
    strengthElement.innerHTML =
        '<div class="strength-bar ' + strength.class + '">' +
            '<div class="strength-fill" style="width: ' + ((result.score + 1) * 20) + '%"></div>' +
        '</div>' +
        '<div class="strength-text">' + strength.text + '</div>';
}

/**
 * Gets the icon HTML from icon type
 * @param {string} iconType - The icon type
 * @returns {string} HTML string for the icon
 */
function getCategoryIconFromType(iconType) {
    const iconMap = {
        folder: 'fa-folder',
        briefcase: 'fa-briefcase',
        user: 'fa-user',
        users: 'fa-users',
        'shopping-cart': 'fa-shopping-cart',
        'credit-card': 'fa-credit-card',
        shield: 'fa-shield-alt',
        gamepad: 'fa-gamepad'
    };
    return iconMap[iconType] || 'fa-folder';
}

/**
 * Gets the icon HTML for a category by looking up the category in the stored categories
 * @param {string} categoryName - The name of the category
 * @returns {Promise<string>} HTML string for the category icon
 */
async function getCategoryIcon(categoryName) {
    try {
        const result = await ipcRenderer.invoke('get-categories');
        if (result.success && result.categories) {
            const category = result.categories.find(function(cat) {
                return cat.name === categoryName;
            });
            if (category && category.icon) {
                return getCategoryIconFromType(category.icon);
            }
        }
    } catch (error) {
        console.error('Error getting category icon:', error);
    }
    return 'fa-folder';
}

function getPasswordStrengthClass(password) {
    const strength = zxcvbn(password);
    const classes = ['very-weak', 'weak', 'fair', 'good', 'strong'];
    return 'strength-' + classes[strength.score];
}

function isValidBase32(secret) {
    return /^[A-Z2-7=]+$/i.test(secret);
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);

        if (appState.settings.clearClipboard) {
            clearClipboardTimer(text);
            const timerId = setTimeout(function() {
                navigator.clipboard.writeText('').catch(function() {});
                showToast(i18n.t('toast.clipboard_cleared'), 'info');
                appState.clipboardTimers.delete(text);
            }, appState.settings.clipboardTimeout * 1000);

            appState.clipboardTimers.set(text, timerId);
        }
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
    }
}

function clearClipboardTimer(text) {
    const timerId = appState.clipboardTimers.get(text);
    if (timerId) {
        clearTimeout(timerId);
        appState.clipboardTimers.delete(text);
    }
}

function clearAllClipboardTimers() {
    appState.clipboardTimers.forEach(function(timerId) {
        clearTimeout(timerId);
    });
    appState.clipboardTimers.clear();
}

function startAutoLockTimer() {
    clearAutoLockTimer();
    if (appState.settings.autoLock && appState.isUnlocked) {
        appState.autoLockTimer = setTimeout(function() {
            lockVault();
        }, appState.settings.autoLockTime * 60 * 1000);
    }
}

function clearAutoLockTimer() {
    if (appState.autoLockTimer) {
        clearTimeout(appState.autoLockTimer);
        appState.autoLockTimer = null;
    }
}

function updateUI() {
    Object.keys(appState.settings).forEach(function(key) {
        const element = elements[key];
        if (element) {
            if (element.type === 'checkbox') {
                element.checked = appState.settings[key];
            } else if (element.type === 'radio') {
                element.checked = appState.settings[key] === element.value;
            } else if (element.tagName === 'SELECT') {
                element.value = appState.settings[key];
            } else {
                element.value = appState.settings[key];
            }
        }
    });
}

async function loadAppVersion() {
    try {
        const result = await ipcRenderer.invoke('get-app-version');
        if (result.success && elements.currentVersion) {
            elements.currentVersion.textContent = result.version;
        }
    } catch (error) {
        console.error('Error loading app version:', error);
    }
}

async function loadUpdateSettings() {
    try {
        const result = await ipcRenderer.invoke('get-update-info');
        if (result.success) {
            appState.settings.autoCheckUpdates = result.autoCheckEnabled;
            if (elements.autoCheckUpdates) {
                elements.autoCheckUpdates.checked = result.autoCheckEnabled;
            }
        }
    } catch (error) {
        console.error('Error loading update settings:', error);
    }
}

async function checkForUpdates() {
    try {
        appState.updateInfo.checking = true;
        updateUpdateStatus();
        await ipcRenderer.invoke('check-for-updates');
    } catch (error) {
        console.error('Error checking for updates:', error);
        appState.updateInfo = {
            checking: false,
            available: false,
            downloading: false,
            downloaded: false,
            error: error
        };
        updateUpdateStatus();
    }
}

async function downloadUpdate() {
    try {
        appState.updateInfo.downloading = true;
        updateInstallButton();
        elements.downloadProgress.style.display = 'block';
        await ipcRenderer.invoke('download-update');
    } catch (error) {
        console.error('Error downloading update:', error);
        appState.updateInfo.downloading = false;
        updateInstallButton();
    }
}

async function installUpdate() {
    try {
        await ipcRenderer.invoke('install-update');
    } catch (error) {
        console.error('Error installing update:', error);
        showToast(i18n.t('toast.install_update_failed'), 'error');
    }
}

function showUpdateModal(info) {
    if (!elements.updateModal) return;

    if (elements.modalCurrentVersion && elements.currentVersion) {
        elements.modalCurrentVersion.textContent = elements.currentVersion.textContent;
    }

    if (elements.modalNewVersion && info.version) {
        elements.modalNewVersion.textContent = info.version;
    }

    if (elements.releaseNotesContent && info.releaseNotes) {
        elements.releaseNotesContent.innerHTML = info.releaseNotes.replace(/\n/g, '<br>');
    }

    elements.downloadProgress.style.display = 'none';
    updateInstallButton();
    elements.updateModal.style.display = 'block';
}

function hideUpdateModal() {
    if (elements.updateModal) {
        elements.updateModal.style.display = 'none';
    }
}

function updateDownloadProgress(progressObj) {
    if (elements.downloadPercentage) {
        elements.downloadPercentage.textContent = Math.round(progressObj.percent) + '%';
    }

    if (elements.downloadProgressFill) {
        elements.downloadProgressFill.style.width = progressObj.percent + '%';
    }
}

function updateInstallButton() {
    if (!elements.installUpdateBtn) return;

    const button = elements.installUpdateBtn;
    const icon = button.querySelector('i');
    const text = button.querySelector('span');

    if (appState.updateInfo.downloading) {
        button.disabled = true;
        icon.className = 'fas fa-spinner fa-spin';
        text.textContent = i18n.t('updater.downloading');
    } else if (appState.updateInfo.downloaded) {
        button.disabled = false;
        icon.className = 'fas fa-rocket';
        text.textContent = i18n.t('updater.install_now');
    } else {
        button.disabled = false;
        icon.className = 'fas fa-download';
        text.textContent = i18n.t('updater.install_now');
    }
}

function updateUpdateStatus() {
    if (!elements.updateStatus) return;

    let statusHTML = '';

    if (appState.updateInfo.checking) {
        statusHTML =
            '<div class="update-status-item info">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<span>' + i18n.t('updater.checking') + '</span>' +
            '</div>';
    } else if (appState.updateInfo.available) {
        statusHTML =
            '<div class="update-status-item success">' +
                '<i class="fas fa-download"></i>' +
                '<span>' + i18n.t('updater.available') + '</span>' +
            '</div>';
    } else if (appState.updateInfo.error) {
        statusHTML =
            '<div class="update-status-item error">' +
                '<i class="fas fa-exclamation-circle"></i>' +
                '<span>' + i18n.t('updater.error') + '</span>' +
            '</div>';
    } else {
        statusHTML =
            '<div class="update-status-item">' +
                '<i class="fas fa-check-circle"></i>' +
                '<span>' + i18n.t('updater.not_available') + '</span>' +
            '</div>';
    }

    elements.updateStatus.innerHTML = statusHTML;
}

function loadSettings() {
    try {
        const saved = localStorage.getItem('secureVaultSettings');
        if (saved) {
            const settings = JSON.parse(saved);
            appState.settings = Object.assign({}, appState.settings, settings);
        }
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

function saveSettings() {
    try {
        localStorage.setItem('secureVaultSettings', JSON.stringify(appState.settings));
    } catch (error) {
        console.error('Error saving settings:', error);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type) {
    type = type || 'info';
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;

    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };

    toast.innerHTML =
        '<div class="toast-content">' +
            '<i class="fas ' + (icons[type] || icons.info) + '"></i>' +
            '<div class="toast-message">' + message + '</div>' +
        '</div>';

    const container = document.getElementById('toast-container');
    if (container) {
        container.appendChild(toast);

        setTimeout(function() {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 4000);

        toast.addEventListener('click', function() {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
}

/**
 * Shows a notification when update is ready to install
 */
function showUpdateReadyNotification() {
    const notification = document.createElement('div');
    notification.className = 'update-notification';
    notification.innerHTML = `
        <div class="update-notification-content">
            <i class="fas fa-download"></i>
            <div class="update-notification-text">
                <h4>${i18n.t('updater.ready_to_install')}</h4>
                <p>${i18n.t('updater.restart_to_apply')}</p>
            </div>
            <div class="update-notification-actions">
                <button class="btn btn-sm btn-outline" onclick="installUpdate()">${i18n.t('updater.install_now')}</button>
                <button class="btn btn-sm btn-outline" onclick="dismissUpdateNotification()">${i18n.t('common.later')}</button>
            </div>
        </div>
    `;

    document.body.appendChild(notification);

    setTimeout(function() {
        notification.classList.add('show');
    }, 100);
}

/**
 * Dismisses the update notification
 */
function dismissUpdateNotification() {
    const notification = document.querySelector('.update-notification');
    if (notification) {
        notification.classList.remove('show');
        setTimeout(function() {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }
}

setInterval(saveSettings, 5000);

window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
    showToast((i18n.t('common.unexpected_error') + ': ' + (e.error ? e.error.message : i18n.t('common.unknown_error'))), 'error');
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
    showToast((i18n.t('common.promise_error') + ': ' + (e.reason ? e.reason.message : i18n.t('common.unknown_error'))), 'error');
});
