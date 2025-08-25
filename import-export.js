/**
 * @fileoverview Enhanced Import/Export System for Secure Vault
 * Supports multiple password managers and formats
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

/**
 * @typedef {Object} ImportResult
 * @property {boolean} success - Whether import was successful
 * @property {number} imported - Number of entries imported
 * @property {number} skipped - Number of entries skipped
 * @property {Array} errors - Array of error messages
 * @property {string} format - Detected format
 */

/**
 * @typedef {Object} PasswordEntry
 * @property {string} id - Unique identifier
 * @property {string} name - Entry name
 * @property {string} username - Username/email
 * @property {string} password - Password
 * @property {string} url - Website URL
 * @property {string} category - Category/folder
 * @property {string} notes - Additional notes
 * @property {Array} tags - Array of tags
 * @property {Date} created - Creation date
 * @property {Date} modified - Last modified date
 */

class ImportExportManager {
    constructor() {
        this.supportedFormats = {
            'csv': 'Generic CSV',
            'json': 'Generic JSON',
            'lastpass': 'LastPass CSV',
            'bitwarden': 'Bitwarden JSON',
            'keepass': 'KeePass CSV',
            'chrome': 'Chrome Passwords CSV',
            'firefox': 'Firefox JSON',
            'winauth': 'WinAuth TXT',
            'securevault': 'Secure Vault (Encrypted)'
        };
    }

    /**
     * Detects the format of imported data
     * @param {string} filePath - Path to the import file
     * @param {string} content - File content
     * @returns {string} Detected format
     */
    detectFormat(filePath, content) {
        const extension = path.extname(filePath).toLowerCase();
        const filename = path.basename(filePath).toLowerCase();

        /* Check by filename patterns */
        if (filename.includes('lastpass')) return 'lastpass';
        if (filename.includes('bitwarden')) return 'bitwarden';
        if (filename.includes('keepass')) return 'keepass';
        if (filename.includes('chrome')) return 'chrome';
        if (filename.includes('firefox')) return 'firefox';
        if (filename.includes('winauth') || extension === '.wa.txt') return 'winauth';
        if (extension === '.svault') return 'securevault';

        /* Check by content structure */
        try {
            const parsed = JSON.parse(content);
            if (parsed.encrypted_data) return 'bitwarden';
            if (parsed.logins) return 'firefox';
            return 'json';
        } catch {
            /* Not JSON, check for WinAuth or CSV */
            const lines = content.split('\n');
            if (lines.length > 0) {
                /* Check for WinAuth format - otpauth URIs */
                const firstLine = lines[0].trim();
                if (firstLine.startsWith('otpauth://')) return 'winauth';
                
                /* Check CSV headers */
                const header = lines[0].toLowerCase();
                if (header.includes('url,username,password')) return 'lastpass';
                if (header.includes('title,username,password,url')) return 'keepass';
                if (header.includes('name,url,username,password')) return 'chrome';
            }
            return 'csv';
        }
    }

    /**
     * Imports data from various password manager formats
     * @param {string} filePath - Path to import file
     * @param {string} masterPassword - Master password for encrypted formats
     * @param {string} contentOverride - Optional content to use instead of reading file
     * @returns {Promise<ImportResult>} Import result
     */
    async importData(filePath, masterPassword = null, contentOverride = null) {
        try {
            let content = contentOverride;
            if (!content) {
                content = await fs.readFile(filePath, 'utf8');
            }
            const format = this.detectFormat(filePath, content);

            console.log(`Detected format: ${format}`);

            let entries = [];

            switch (format) {
            case 'lastpass':
                entries = this.parseLastPassCSV(content);
                break;
            case 'bitwarden':
                entries = this.parseBitwardenJSON(content);
                break;
            case 'keepass':
                entries = this.parseKeePassCSV(content);
                break;
            case 'chrome':
                entries = this.parseChromeCSV(content);
                break;
            case 'firefox':
                entries = this.parseFirefoxJSON(content);
                break;
            case 'winauth':
                entries = this.parseWinAuthTXT(content);
                break;
            case 'securevault':
                entries = await this.parseSecureVaultBackup(content, masterPassword);
                break;
            case 'csv':
                entries = this.parseGenericCSV(content);
                break;
            case 'json':
                entries = this.parseGenericJSON(content);
                break;
            default:
                throw new Error(`Unsupported format: ${format}`);
            }

            const processed = this.processEntries(entries);

            return {
                success: true,
                imported: processed.valid.length,
                skipped: processed.invalid.length,
                errors: processed.errors,
                format: format,
                entries: processed.valid
            };

        } catch (error) {
            console.error('Import error:', error);
            return {
                success: false,
                imported: 0,
                skipped: 0,
                errors: [error.message],
                format: 'unknown'
            };
        }
    }

    /**
     * Parses LastPass CSV format
     * @param {string} content - CSV content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseLastPassCSV(content) {
        const lines = content.split('\n');
        const entries = [];

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            try {
                const columns = this.parseCSVLine(line);
                if (columns.length >= 6) {
                    /* LastPass format: url,username,password,totp,extra,name,grouping,fav */
                    entries.push({
                        name: columns[5] || 'Imported Entry', // name column
                        url: columns[0] || '', // url column
                        username: columns[1] || '', // username column
                        password: columns[2] || '', // password column  
                        notes: columns[4] || '', // extra column (notes)
                        category: columns[6] || 'Imported', // grouping column
                        tags: ['lastpass']
                    });
                }
            } catch (error) {
                console.warn(`Failed to parse line ${i}: ${error.message}`);
            }
        }

        return entries;
    }

    /**
     * Parses Bitwarden JSON format
     * @param {string} content - JSON content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseBitwardenJSON(content) {
        const data = JSON.parse(content);
        const entries = [];

        if (data.items && Array.isArray(data.items)) {
            for (const item of data.items) {
                if (item.type === 1 && item.login) { // Login type
                    entries.push({
                        name: item.name || 'Imported Entry',
                        url: item.login.uris?.[0]?.uri || '',
                        username: item.login.username || '',
                        password: item.login.password || '',
                        notes: item.notes || '',
                        category: item.folderId ? `Folder_${item.folderId}` : 'Imported',
                        tags: []
                    });
                }
            }
        }

        return entries;
    }

    /**
     * Parses KeePass CSV format
     * @param {string} content - CSV content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseKeePassCSV(content) {
        const lines = content.split('\n');
        const entries = [];

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            try {
                const columns = this.parseCSVLine(line);
                if (columns.length >= 4) {
                    entries.push({
                        name: columns[0] || 'Imported Entry',
                        username: columns[1] || '',
                        password: columns[2] || '',
                        url: columns[3] || '',
                        notes: columns[4] || '',
                        category: columns[5] || 'Imported',
                        tags: []
                    });
                }
            } catch (error) {
                console.warn(`Failed to parse line ${i}: ${error.message}`);
            }
        }

        return entries;
    }

    /**
     * Parses Chrome passwords CSV format
     * @param {string} content - CSV content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseChromeCSV(content) {
        const lines = content.split('\n');
        const entries = [];

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            try {
                const columns = this.parseCSVLine(line);
                if (columns.length >= 4) {
                    /* Chrome format: name,url,username,password */
                    const url = columns[1] || '';
                    const domain = this.extractDomain(url);

                    entries.push({
                        name: columns[0] || domain || 'Imported Entry',
                        url: url,
                        username: columns[2] || '',
                        password: columns[3] || '',
                        notes: '',
                        category: 'Chrome Import',
                        tags: ['chrome']
                    });
                }
            } catch (error) {
                console.warn(`Failed to parse line ${i}: ${error.message}`);
            }
        }

        return entries;
    }

    /**
     * Parses Firefox JSON format
     * @param {string} content - JSON content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseFirefoxJSON(content) {
        const data = JSON.parse(content);
        const entries = [];

        if (data.logins && Array.isArray(data.logins)) {
            for (const login of data.logins) {
                const domain = this.extractDomain(login.hostname);

                entries.push({
                    name: login.httpRealm || domain || 'Imported Entry',
                    url: login.hostname || '',
                    username: login.username || '',
                    password: login.password || '',
                    notes: '',
                    category: 'Firefox Import',
                    tags: ['firefox']
                });
            }
        }

        return entries;
    }

    /**
     * Parses WinAuth TXT format (otpauth URIs)
     * @param {string} content - TXT content with otpauth URIs
     * @returns {Array<PasswordEntry>} Parsed TOTP entries
     */
    parseWinAuthTXT(content) {
        const lines = content.split('\n');
        const entries = [];

        for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine || !trimmedLine.startsWith('otpauth://')) {
                continue;
            }

            try {
                const url = new URL(trimmedLine);
                
                /* Only support TOTP for now */
                if (url.protocol !== 'otpauth:' || url.hostname !== 'totp') {
                    console.warn(`Unsupported otpauth type: ${url.hostname}`);
                    continue;
                }

                const pathParts = url.pathname.substring(1); // Remove leading '/'
                const params = url.searchParams;

                /* Parse label (account name and issuer) */
                let accountName = pathParts;
                let issuer = params.get('issuer') || '';

                /* Handle "Issuer:Account" format */
                if (pathParts.includes(':')) {
                    const [issuerFromLabel, account] = pathParts.split(':', 2);
                    if (!issuer) {
                        issuer = decodeURIComponent(issuerFromLabel);
                    }
                    accountName = decodeURIComponent(account);
                } else {
                    accountName = decodeURIComponent(pathParts);
                }

                const secret = params.get('secret');
                if (!secret) {
                    console.warn('Missing secret in otpauth URI');
                    continue;
                }

                /* Validate Base32 secret */
                if (!/^[A-Z2-7=]+$/i.test(secret)) {
                    console.warn('Invalid Base32 secret format');
                    continue;
                }

                const digits = parseInt(params.get('digits')) || 6;
                const period = parseInt(params.get('period')) || 30;

                /* Handle Battle.net special case */
                let serial = params.get('serial');
                if (serial) {
                    accountName = `${accountName} (${serial})`;
                }

                entries.push({
                    name: accountName || 'WinAuth Import',
                    issuer: issuer || 'WinAuth Import', 
                    secret: secret,
                    digits: digits,
                    period: period,
                    category: 'WinAuth Import',
                    tags: ['winauth', 'totp']
                });

            } catch (error) {
                console.warn(`Failed to parse otpauth URI: ${error.message}`);
                continue;
            }
        }

        return entries;
    }

    /**
     * Parses generic CSV format
     * @param {string} content - CSV content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseGenericCSV(content) {
        const lines = content.split('\n');
        const entries = [];
        const header = lines[0]?.toLowerCase() || '';

        /* Try to detect column positions */
        const nameCol = this.findColumn(header, ['name', 'title', 'site']);
        const urlCol = this.findColumn(header, ['url', 'website', 'site']);
        const usernameCol = this.findColumn(header, ['username', 'user', 'email']);
        const passwordCol = this.findColumn(header, ['password', 'pass']);
        const notesCol = this.findColumn(header, ['notes', 'note', 'comment']);

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            try {
                const columns = this.parseCSVLine(line);

                entries.push({
                    name: columns[nameCol] || columns[0] || 'Imported Entry',
                    url: columns[urlCol] || '',
                    username: columns[usernameCol] || '',
                    password: columns[passwordCol] || '',
                    notes: columns[notesCol] || '',
                    category: 'Imported',
                    tags: []
                });
            } catch (error) {
                console.warn(`Failed to parse line ${i}: ${error.message}`);
            }
        }

        return entries;
    }

    /**
     * Parses generic JSON format
     * @param {string} content - JSON content
     * @returns {Array<PasswordEntry>} Parsed entries
     */
    parseGenericJSON(content) {
        const data = JSON.parse(content);
        const entries = [];

        if (Array.isArray(data)) {
            for (const item of data) {
                entries.push({
                    name: item.name || item.title || item.site || 'Imported Entry',
                    url: item.url || item.website || item.site || '',
                    username: item.username || item.user || item.email || '',
                    password: item.password || item.pass || '',
                    notes: item.notes || item.note || item.comment || '',
                    category: item.category || item.folder || 'Imported',
                    tags: item.tags || []
                });
            }
        }

        return entries;
    }

    /**
     * Processes entries and validates them
     * @param {Array<PasswordEntry>} entries - Raw entries
     * @returns {Object} Processed result with valid/invalid entries
     */
    processEntries(entries) {
        const valid = [];
        const invalid = [];
        const errors = [];

        for (const entry of entries) {
            try {
                /* Check if this is a TOTP entry */
                if (entry.secret && entry.issuer !== undefined) {
                    /* TOTP entry validation */
                    if (!entry.name || !entry.secret) {
                        invalid.push(entry);
                        errors.push(`TOTP entry missing required fields: ${entry.name || 'Unknown'}`);
                        continue;
                    }

                    /* Generate TOTP entry */
                    const processedEntry = {
                        id: crypto.randomUUID(),
                        name: this.sanitizeString(entry.name),
                        issuer: this.sanitizeString(entry.issuer || ''),
                        secret: entry.secret,
                        digits: entry.digits || 6,
                        period: entry.period || 30,
                        category: this.sanitizeString(entry.category || 'Imported'),
                        tags: Array.isArray(entry.tags) ? entry.tags : [],
                        type: 'totp',
                        created: new Date(),
                        modified: new Date()
                    };

                    valid.push(processedEntry);
                } else {
                    /* Password entry validation */
                    if (!entry.name || !entry.password) {
                        invalid.push(entry);
                        errors.push(`Password entry missing required fields: ${entry.name || 'Unknown'}`);
                        continue;
                    }

                    /* Generate password entry */
                    const processedEntry = {
                        id: crypto.randomUUID(),
                        name: this.sanitizeString(entry.name),
                        username: this.sanitizeString(entry.username || ''),
                        password: entry.password,
                        url: this.sanitizeUrl(entry.url || ''),
                        category: this.sanitizeString(entry.category || 'Imported'),
                        notes: this.sanitizeString(entry.notes || ''),
                        tags: Array.isArray(entry.tags) ? entry.tags : [],
                        type: 'password',
                        created: new Date(),
                        modified: new Date()
                    };

                    valid.push(processedEntry);
                }
            } catch (error) {
                invalid.push(entry);
                errors.push(`Error processing entry: ${error.message}`);
            }
        }

        return { valid, invalid, errors };
    }

    /**
     * Exports vault data in various formats
     * @param {Array<PasswordEntry>} entries - Entries to export
     * @param {string} format - Export format
     * @param {string} filePath - Export file path
     * @param {string} password - Password for encrypted exports
     * @returns {Promise<boolean>} Success status
     */
    async exportData(entries, format, filePath, password = null) {
        try {
            let content = '';

            switch (format) {
            case 'csv':
                content = this.exportToCSV(entries);
                break;
            case 'json':
                content = this.exportToJSON(entries);
                break;
            case 'securevault':
                content = await this.exportToSecureVault(entries, password);
                break;
            case 'lastpass':
                content = this.exportToLastPassCSV(entries);
                break;
            case 'bitwarden':
                content = this.exportToBitwardenJSON(entries);
                break;
            default:
                throw new Error(`Unsupported export format: ${format}`);
            }

            await fs.writeFile(filePath, content, 'utf8');
            return true;

        } catch (error) {
            console.error('Export error:', error);
            throw error;
        }
    }

    /**
     * Exports to CSV format
     * @param {Array<PasswordEntry>} entries - Entries to export
     * @returns {string} CSV content
     */
    exportToCSV(entries) {
        const headers = ['Name', 'URL', 'Username', 'Password', 'Category', 'Notes', 'Tags'];
        const rows = [headers.join(',')];

        for (const entry of entries) {
            const row = [
                this.escapeCsvField(entry.name),
                this.escapeCsvField(entry.url),
                this.escapeCsvField(entry.username),
                this.escapeCsvField(entry.password),
                this.escapeCsvField(entry.category),
                this.escapeCsvField(entry.notes),
                this.escapeCsvField(entry.tags.join(';'))
            ];
            rows.push(row.join(','));
        }

        return rows.join('\n');
    }

    /**
     * Exports to JSON format
     * @param {Array<PasswordEntry>} entries - Entries to export
     * @returns {string} JSON content
     */
    exportToJSON(entries) {
        const exportData = {
            version: '1.0',
            exported: new Date().toISOString(),
            entries: entries.map(entry => ({
                ...entry,
                created: entry.created?.toISOString(),
                modified: entry.modified?.toISOString()
            }))
        };

        return JSON.stringify(exportData, null, 2);
    }

    /**
     * Exports to encrypted Secure Vault format
     * @param {Array<PasswordEntry>} entries - Entries to export
     * @param {string} password - Encryption password
     * @returns {Promise<string>} Encrypted content
     */
    async exportToSecureVault(entries, password) {
        if (!password) {
            throw new Error(typeof i18n !== 'undefined' ? i18n.t('errors.password_required_encrypted') : 'Password required for encrypted export');
        }

        const data = {
            version: '1.0',
            exported: new Date().toISOString(),
            entries: entries
        };

        const jsonData = JSON.stringify(data);
        const compressed = await gzip(Buffer.from(jsonData, 'utf8'));

        /* Encrypt the compressed data */
        const salt = crypto.randomBytes(32);
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

        let encrypted = cipher.update(compressed);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        const result = {
            algorithm: 'aes-256-cbc',
            salt: salt.toString('hex'),
            iv: iv.toString('hex'),
            data: encrypted.toString('hex')
        };

        return JSON.stringify(result, null, 2);
    }

    /**
     * Parses encrypted Secure Vault backup format
     * @param {string} content - Encrypted backup content
     * @param {string} password - Decryption password
     * @returns {Promise<Array<PasswordEntry>>} Parsed entries
     */
    async parseSecureVaultBackup(content, password) {
        if (!password) {
            throw new Error(typeof i18n !== 'undefined' ? i18n.t('errors.password_required_backup') : 'Password required for encrypted backup');
        }

        try {
            const backupData = JSON.parse(content);

            if (!backupData.algorithm || !backupData.salt || !backupData.data) {
                throw new Error(typeof i18n !== 'undefined' ? i18n.t('errors.invalid_backup_format') : 'Invalid backup format');
            }

            /* Decrypt the data */
            const salt = Buffer.from(backupData.salt, 'hex');
            const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
            const iv = Buffer.from(backupData.iv, 'hex');

            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

            let decrypted = decipher.update(Buffer.from(backupData.data, 'hex'));
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            /* Decompress if needed */
            const decompressed = await gunzip(decrypted);
            const data = JSON.parse(decompressed.toString('utf8'));

            return data.entries || [];
        } catch (error) {
            throw new Error(`Failed to decrypt backup: ${error.message}`);
        }
    }

    /**
     * Exports to LastPass CSV format
     * @param {Array<PasswordEntry>} entries - Entries to export
     * @returns {string} LastPass CSV content
     */
    exportToLastPassCSV(entries) {
        const headers = ['url', 'username', 'password', 'extra', 'name', 'grouping', 'fav'];
        const rows = [headers.join(',')];

        for (const entry of entries) {
            const row = [
                this.escapeCsvField(entry.url),
                this.escapeCsvField(entry.username),
                this.escapeCsvField(entry.password),
                this.escapeCsvField(entry.notes),
                this.escapeCsvField(entry.name),
                this.escapeCsvField(entry.category),
                '0'
            ];
            rows.push(row.join(','));
        }

        return rows.join('\n');
    }

    /**
     * Exports to Bitwarden JSON format
     * @param {Array<PasswordEntry>} entries - Entries to export
     * @returns {string} Bitwarden JSON content
     */
    exportToBitwardenJSON(entries) {
        const bitwardenData = {
            encrypted: false,
            folders: [
                {
                    id: '1',
                    name: 'Imported'
                }
            ],
            items: entries.map(entry => ({
                id: entry.id,
                organizationId: null,
                folderId: '1',
                type: 1, // Login type
                name: entry.name,
                notes: entry.notes,
                favorite: false,
                login: {
                    username: entry.username,
                    password: entry.password,
                    totp: null,
                    uris: entry.url ? [{
                        match: null,
                        uri: entry.url
                    }] : []
                },
                collectionIds: [],
                revisionDate: entry.modified || new Date().toISOString(),
                creationDate: entry.created || new Date().toISOString(),
                deletedDate: null
            }))
        };

        return JSON.stringify(bitwardenData, null, 2);
    }

    /**
     * Utility functions
     */

    /**
     * Parses a CSV line handling quoted fields
     * @param {string} line - CSV line
     * @returns {Array<string>} Parsed columns
     */
    parseCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;
        let i = 0;

        while (i < line.length) {
            const char = line[i];
            const nextChar = line[i + 1];

            if (char === '"') {
                if (inQuotes && nextChar === '"') {
                    current += '"';
                    i += 2;
                    continue;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (char === ',' && !inQuotes) {
                result.push(current);
                current = '';
            } else {
                current += char;
            }

            i++;
        }

        result.push(current);
        return result;
    }

    /**
     * Finds column index by name
     * @param {string} header - CSV header
     * @param {Array<string>} names - Possible column names
     * @returns {number} Column index or -1
     */
    findColumn(header, names) {
        const columns = header.split(',');
        for (let i = 0; i < columns.length; i++) {
            const col = columns[i].trim().toLowerCase();
            if (names.some(name => col.includes(name))) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Extracts domain from URL
     * @param {string} url - URL
     * @returns {string} Domain
     */
    extractDomain(url) {
        try {
            const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
            return urlObj.hostname;
        } catch {
            return url;
        }
    }

    /**
     * Sanitizes string input
     * @param {string} str - Input string
     * @returns {string} Sanitized string
     */
    sanitizeString(str) {
        return String(str || '').trim().substring(0, 1000);
    }

    /**
     * Sanitizes URL input
     * @param {string} url - Input URL
     * @returns {string} Sanitized URL
     */
    sanitizeUrl(url) {
        const sanitized = this.sanitizeString(url);
        if (!sanitized) return '';

        if (!sanitized.startsWith('http://') && !sanitized.startsWith('https://')) {
            return `https://${sanitized}`;
        }

        return sanitized;
    }

    /**
     * Escapes CSV field
     * @param {string} field - Field value
     * @returns {string} Escaped field
     */
    escapeCsvField(field) {
        const str = String(field || '');
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    }
}

module.exports = { ImportExportManager };

