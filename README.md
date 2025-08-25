# Secure Vault

A desktop password manager and two-factor authenticator built with Electron. Provides local data storage with AES-256 encryption and cross-platform compatibility for Windows, macOS, and Linux.

## Features

### Password Management
- **Local Storage** - AES-256 encrypted storage with PBKDF2 key derivation
- **Password Generator** - Configurable password generation with cryptographically secure randomness
- **Strength Analysis** - Real-time password strength assessment using zxcvbn library
- **Category Organization** - User-defined categories with customizable colors and icons
- **Search System** - Real-time search with advanced filtering options
- **Quick Actions** - One-click copy operations with configurable clipboard clearing

### Two-Factor Authentication
- **TOTP Generation** - RFC 6238 compliant time-based one-time passwords
- **Desktop QR Scanning** - Screen capture QR code scanning for easy account setup
- **Multi-Account Support** - Unlimited TOTP accounts with real-time countdown timers
- **Manual Entry** - Alternative setup method for accounts without QR codes
- **Flexible Configuration** - Support for 6/8 digit codes and 30/60 second periods

### Import/Export System
- **Multiple Format Support** - LastPass CSV, Bitwarden JSON, KeePass CSV, Chrome passwords, Firefox logins, WinAuth TXT
- **Auto-Format Detection** - Automatic detection of import file formats
- **Encrypted Backups** - Custom .svault format with compression and AES-256 encryption
- **Data Validation** - Entry validation and sanitization during import process
- **Bulk Operations** - Import thousands of entries with error reporting

### Security Features
- **Zero-Knowledge Architecture** - Master password never stored, only salted bcrypt hash
- **Session Management** - Configurable auto-lock with user activity monitoring
- **Rate Limiting** - Failed password attempt protection with exponential backoff
- **Memory Protection** - Secure handling of sensitive data with automatic cleanup
- **Vault Recovery** - Automatic recovery system for corrupted vault data
- **Offline Operation** - No network connectivity required for core functionality

### Advanced Features
- **Security Audit** - Password analysis for weak, reused, old, and compromised credentials
- **Advanced Search** - Complex filtering by name, username, URL, category, and tags
- **Category Management** - Create and organize custom categories with visual indicators
- **Tag System** - Tag-based organization for flexible password categorization
- **Desktop Integration** - System tray support, global shortcuts, and auto-startup

### User Interface
- **Internationalization** - Full English and German language support with 900+ translations
- **Responsive Design** - Adaptive layout for various screen sizes and resolutions
- **Dark Theme** - Modern interface optimized for extended use
- **Toast Notifications** - Non-intrusive feedback system for user actions
- **Custom Window Controls** - Native-style title bar with minimize, maximize, and close

### Update System
- **Auto-Updates** - Automatic update checking and installation (Windows/macOS)
- **Progress Tracking** - Real-time download progress with detailed status information
- **Version Management** - Support for update deferral and version skipping
- **Release Notes** - Integrated display of version changes and improvements

## Technical Specifications

### Encryption
- **Algorithm** - AES-256-CBC for data encryption
- **Key Derivation** - PBKDF2 with SHA-512 (100,000 iterations)
- **Random Generation** - Node.js crypto module for secure randomness
- **Salt Storage** - Unique salt per vault for key derivation

### Data Storage
- **Format** - Encrypted JSON with electron-store
- **Location** - Local application data directory
- **Backup** - Compressed and encrypted export files (.svault)
- **Recovery** - Automatic corruption detection and recovery

### Platform Support
- **Windows** - Windows 10 and later (x64)
- **macOS** - macOS 10.14 (Mojave) and later (x64/ARM64)
- **Linux** - Ubuntu 18.04+ and equivalent distributions (x64)

### System Requirements
- **Memory** - 512MB available RAM minimum
- **Storage** - 350MB free disk space
- **Display** - 1024x768 minimum resolution
- **Network** - Optional for updates only

## Installation

### From Releases
1. Download the appropriate installer for your operating system from the releases page
2. Run the installer (Windows: .exe, macOS: .dmg, Linux: .AppImage/.deb/.rpm)
3. Launch the application and create your master password
4. Configure security settings as needed

### Build from Source
```bash
# Clone repository
git clone https://github.com/bavamont/secure-vault.git
cd secure-vault

# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build
```

## Configuration

### Security Settings
- **Auto-lock timeout** - 5 to 60 minutes of inactivity
- **Clipboard clearing** - 10 seconds to 2 minutes after copy
- **Activity monitoring** - Mouse, keyboard, and touch event detection
- **Session management** - Automatic vault locking on system sleep/lock

### Import Configuration
Supported import formats:
- **LastPass** - CSV export from LastPass vault
- **Bitwarden** - JSON export from Bitwarden vault
- **KeePass** - CSV export from KeePass database
- **Chrome** - CSV export from Chrome password manager
- **Firefox** - JSON export from Firefox password manager
- **WinAuth** - TXT export with otpauth URIs for TOTP accounts
- **Generic CSV/JSON** - Custom formats with automatic field mapping

### Export Formats
Available export formats:
- **Secure Vault** - Encrypted .svault format (recommended)
- **Generic JSON** - Unencrypted JSON for broad compatibility
- **Generic CSV** - Unencrypted CSV for spreadsheet applications
- **LastPass CSV** - Format compatible with LastPass import
- **Bitwarden JSON** - Format compatible with Bitwarden import

## Security Considerations

### Master Password
- Not recoverable if forgotten - results in complete data loss
- Should be unique and not used for any other accounts
- Strength validation provided during setup
- Consider using a passphrase with multiple words

### Backup Strategy
- Regular exports recommended for data protection
- Store backup files in secure, separate locations
- Encrypted .svault format provides additional protection
- Test restore process periodically

### Data Protection
- All data stored locally with no cloud synchronization
- Vault files encrypted with user's master password
- Application data isolated from other system applications
- Secure deletion of temporary files and clipboard data

### Network Security
- No network communication required for core functionality
- Update checks use HTTPS with certificate validation
- No telemetry or usage data collection
- Offline operation maintains complete privacy

## Keyboard Shortcuts

### Global Shortcuts (configurable)
- **Quick Access** - Ctrl+Shift+V (default)
- **Auto-Lock** - Ctrl+Shift+L (default)

### Application Shortcuts
- **Lock Vault** - Ctrl+L
- **Search** - Ctrl+F
- **New Password** - Ctrl+N
- **Settings** - Ctrl+, (comma)

## Development

### Architecture
- **Main Process** - Electron main process handles system integration and security
- **Renderer Process** - UI handling with secure communication via IPC
- **Modular Design** - Separate modules for import/export, i18n, and security functions

### Code Quality
- **ESLint** - Configured linting rules for code consistency
- **JSDoc** - Comprehensive documentation for all functions
- **Error Handling** - Graceful degradation with user-friendly error messages
- **Type Safety** - JSDoc type annotations for better code reliability

### Testing
```bash
# Run linter
npm run lint

# Run tests
npm test

# Development mode
npm run dev
```

## Troubleshooting

### Common Issues
- **Vault corruption** - Application includes automatic recovery system
- **Import failures** - Check file format and encoding (UTF-8 required)
- **Update problems** - Manual download available if auto-update fails
- **Performance** - Large vaults (1000+ entries) may have slower search

### Data Recovery
- **Corrupted vault** - Application attempts automatic recovery on startup
- **Lost master password** - No recovery possible, requires fresh start
- **Import errors** - Check import file format and review error messages
- **Export issues** - Verify disk space and file permissions

## Credits

**Developed by**: www.bavamont.com

**Dependencies**:
- Electron - Cross-platform desktop framework
- bcrypt - Password hashing library
- speakeasy - TOTP code generation
- jsQR - QR code scanning functionality
- zxcvbn - Password strength estimation
- electron-store - Encrypted data persistence
- electron-updater - Application update system

**Architecture**:
- Zero-knowledge security design
- Local-first data storage
- Modular component architecture
- Cross-platform compatibility layer