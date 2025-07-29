# Secure Vault

A desktop password manager and two-factor authenticator with military-grade encryption. Built with Electron for cross-platform compatibility and designed with security-first principles for everyday users and security professionals.

## Features

### Password Management
- **Secure Storage** - Military-grade encryption protects all stored passwords
- **Password Generator** - Create cryptographically secure passwords with customizable parameters
- **Strength Analysis** - Real-time password strength assessment using zxcvbn
- **Category Organization** - Organize passwords by type (Website, App, Email, Social, Financial, Other)
- **Smart Search** - Instantly find passwords by name, username, or URL
- **Quick Actions** - One-click copy username/password with automatic clipboard clearing

### Two-Factor Authentication
- **TOTP Code Generation** - Generate time-based one-time passwords (TOTP) for 2FA
- **QR Code Scanning** - Multiple scanning methods including desktop screen capture
- **Multi-Account Support** - Manage unlimited 2FA accounts with real-time countdown timers
- **Standard Compliance** - Supports RFC 6238 TOTP standard
- **Visual Indicators** - Real-time countdown circles and expiration warnings

### Advanced Security Features
- **Master Password Protection** - Single master password secures entire vault
- **Auto-Lock** - Configurable automatic locking after inactivity
- **Clipboard Security** - Automatic clipboard clearing after configurable timeout
- **Secure Backup** - Encrypted export/import with JSON format
- **Data Isolation** - Complete offline operation with no cloud dependencies
- **Memory Protection** - Secure password handling with automatic cleanup

### User Experience
- **Multi-Language Support** - Available in English and German with automatic detection
- **Modern Interface** - Clean, intuitive dark theme design optimized for daily use
- **Auto-Updates** - Seamless automatic update system with progress tracking
- **Cross-Platform** - Native experience on Windows, macOS, and Linux
- **Keyboard Shortcuts** - Efficient workflows with comprehensive keyboard support
- **Responsive Design** - Optimized for various screen sizes and resolutions

## Core Capabilities

### Password Vault
- **Unlimited Storage** - Store unlimited passwords with detailed metadata
- **Rich Metadata** - Name, username, password, URL, category, and notes
- **Import/Export** - Secure vault backup and restore functionality
- **Search & Filter** - Advanced filtering by category and real-time search
- **Password Health** - Visual indicators for password strength and security
- **URL Integration** - Direct website access from stored entries

### Authenticator Engine
- **TOTP Standards** - Full RFC 6238 compliance with industry-standard algorithms
- **Flexible Configuration** - Support for 6/8 digit codes and 30/60 second periods
- **Visual Countdown** - Real-time visual indicators for code expiration
- **Manual Entry** - Alternative input method for QR-less setup
- **Account Management** - Edit, delete, and organize 2FA accounts

### Security Architecture
- **End-to-End Encryption** - All data encrypted at rest using AES-256
- **Zero-Knowledge** - Master password never stored, only salted hash
- **Secure Random** - Cryptographically secure random number generation
- **Memory Safety** - Secure memory handling with automatic cleanup
- **Session Management** - Configurable auto-lock with activity monitoring
- **Backup Security** - Encrypted exports with integrity verification

## Quick Start

### Initial Setup
1. **Create Master Password** - Choose a strong, unique master password for vault access
2. **Configure Security** - Set auto-lock timeout and clipboard clearing preferences
3. **Add First Password** - Store your first password to get familiar with the interface
4. **Setup 2FA** - Add your first authenticator account using QR scanning or manual entry

### Daily Workflow
1. **Unlock Vault** - Enter master password to access your secure data
2. **Quick Access** - Use search to quickly find passwords or 2FA codes
3. **Copy Credentials** - One-click copying with automatic clipboard clearing
4. **Auto-Lock** - Vault automatically locks when you step away

### Advanced Usage
1. **Desktop QR Scanning** - Scan QR codes displayed anywhere on your screen
2. **Bulk Import** - Import existing password data using JSON format
3. **Security Audit** - Review password strength and update weak credentials
4. **Backup Management** - Regular encrypted backups for data protection

## Interface Overview

### Main Navigation
- **Passwords** - Complete password management with search and categories
- **Authenticator** - Two-factor authentication code generation and management
- **Settings** - Security preferences, backup/restore, and update management
- **Help** - Comprehensive documentation and getting started guide

### Security Features
- **Master Password Setup** - Initial vault creation with strength validation
- **Lock Screen** - Secure authentication barrier with password visibility toggle
- **Auto-Lock Timer** - Configurable inactivity timeout with user activity detection
- **Clipboard Protection** - Automatic clearing prevents credential exposure

## Security Features

### Encryption & Protection
- **AES-256 Encryption** - Military-grade encryption for all stored data
- **PBKDF2 Key Derivation** - Secure master password hashing with salt
- **Secure Random Generation** - Cryptographically secure randomness for all operations
- **Memory Protection** - Secure handling of sensitive data in memory
- **Zero-Knowledge Architecture** - Master password never stored or transmitted

### Access Control
- **Master Password** - Single point of authentication for vault access
- **Auto-Lock** - Configurable automatic locking (5-60 minutes)
- **Activity Monitoring** - Mouse, keyboard, and touch event detection
- **Session Management** - Secure session handling with proper cleanup
- **Failed Attempt Protection** - Protection against brute force attacks

### Data Security
- **Offline Operation** - Complete functionality without internet connection
- **Local Storage** - All data stored locally with user control
- **Encrypted Backups** - Secure export format with integrity verification
- **Secure Import** - Safe restoration from encrypted backup files
- **Data Isolation** - Application data isolated from system and other apps

## Installation & Setup

1. **Download** - Get the latest release for your operating system
2. **Install** - Run installer (Windows), mount DMG (macOS), or extract archive (Linux)
3. **Launch** - Start Secure Vault application
4. **Create Vault** - Set up master password and security preferences
5. **Import Data** - Optionally import existing password data
6. **Configure Settings** - Customize auto-lock, clipboard, and backup preferences

## Supported Platforms

### Desktop Operating Systems
- **Windows** - Windows 10 and later (x64)
- **macOS** - macOS 10.14 (Mojave) and later
- **Linux** - Ubuntu 18.04+ and equivalent distributions

### System Requirements
- **RAM** - Minimum 512MB available memory
- **Storage** - 350MB free disk space for installation
- **Display** - 1024x768 minimum resolution (1400x900+ recommended)
- **Network** - Internet connection for updates only (optional)

## Security Disclaimer

🔒 **Security Notice**: This application stores sensitive data locally and requires proper security practices.

### User Responsibilities
- **Master Password** - Choose a strong, unique master password you haven't used elsewhere
- **Backup Security** - Store backup files in secure locations with appropriate permissions
- **Device Security** - Ensure your device is secured with proper access controls
- **Update Management** - Keep the application updated for latest security improvements
- **Physical Security** - Protect device access and enable auto-lock features

### Security Considerations
- **Local Storage** - All data stored locally; no cloud synchronization
- **Master Password Recovery** - No password recovery; master password loss means data loss
- **Backup Strategy** - Regular backups essential for data protection
- **Multi-Device** - Manual export/import required for multi-device usage

## Use Cases

### Personal Users
- **Password Management** - Secure storage for all personal accounts
- **2FA Setup** - Easy two-factor authentication for online accounts
- **Digital Security** - Comprehensive personal cybersecurity solution

### Security Professionals
- **Client Demonstrations** - Show best practices for password management
- **Security Training** - Educational tool for 2FA and password security
- **Personal Security** - Professional-grade tool for personal use
- **Audit Compliance** - Meet security requirements with encrypted storage

### Developers
- **Development Accounts** - Secure storage for development credentials
- **API Keys** - Safe storage for sensitive development tokens
- **2FA Testing** - Generate TOTP codes for application testing
- **Security Research** - Analyze TOTP implementations and QR code handling

## Credits

**Developed by**: www.bavamont.com

**Built for**: Security-conscious users and professionals

**Powered by**:
- Electron framework for cross-platform desktop applications
- bcrypt for secure password hashing
- speakeasy for TOTP code generation
- jsQR for QR code scanning technology
- zxcvbn for password strength analysis
- Modern web technologies (HTML5, CSS3, JavaScript)

**Special Features**:
- Military-grade encryption standards
- Zero-knowledge security architecture
- Comprehensive 2FA support
- Modern responsive interface