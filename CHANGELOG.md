# Changelog

All notable changes to the AppCloner Tool project.

## [2.0.0] - 2024-11-30

### ✨ Added
- **Legacy Decryption Support**: New `LegacyDecryptor.java` class for backward compatibility
  - Decrypts old AppCloner versions' strings.properties files
  - Uses AES-256-ECB with PKCS5 padding
  - Includes validation helpers for decrypted format
  - Added new `LEGACY_STRINGS_PROPERTIES` data mode

- **Comprehensive Documentation**:
  - `README.md`: Complete usage guide and technical documentation
  - `IMPROVEMENTS.md`: Detailed summary of all improvements
  - `ARCHITECTURE.md`: Full architecture overview with diagrams
  - `CHANGELOG.md`: This file

### 🔧 Changed
- **Code Restructuring**:
  - Extracted all inner classes from MainActivity to separate files
  - `DataMode.java`: Now standalone enum with documentation
  - `OperationMode.java`: Now standalone enum with documentation
  - `SavableContent.java`: Separate class with enhanced validation
  - `CryptoConstants.java`: Standalone constants class
  - `CryptoUtils.java`: Standalone utility class
  - `PropertiesParser.java`: Standalone parser class

- **UI Improvements**:
  - Changed tab layout from fixed to scrollable mode
  - Updated tab names for clarity:
    - "Simple" → ".DAT File"
    - "Chained" → "Chained Props"
    - "Settings" → "Clone Settings"
    - Added "Legacy Props" tab
  - Better visual hierarchy with Material Design components

- **Documentation Improvements**:
  - Added Javadoc comments to all classes
  - Added inline documentation for complex algorithms
  - Documented all constants and their purposes
  - Improved method-level documentation

### 🐛 Fixed
- Corrected `CHAINED_MAX_DEPTH` documentation (was 25, now correctly 50)
- Added missing `CHAINED_ENCRYPTION_CHUNK_COUNT` constant (25)
- Fixed inconsistent naming in legacy mode references
- Improved error messages throughout the application

### 🗑️ Removed
- Obsolete `encryptSingleProperties()` method (replaced with legacy warning)
- Removed unused inner class definitions from MainActivity

### 📦 Commits
```
515bb76 docs: Add comprehensive architecture documentation
d233eb7 docs: Add comprehensive improvements summary document
d2812f1 refactor: Restructure codebase for better maintainability and add legacy decryption support
```

### 🎯 Migration Guide
No breaking changes. All existing functionality preserved.

**For Users:**
- New "Legacy Props" tab available for old file formats
- All other modes work exactly as before
- UI is more intuitive with clearer tab names

**For Developers:**
- Classes now in separate files for better organization
- Same public API, just reorganized
- See `ARCHITECTURE.md` for new structure details

---

## [1.x.x] - Previous Versions

### Earlier Changes
- Initial implementation of encryption/decryption modes
- Support for timestamp DAT, chained properties, clone settings, and app data
- Material Design UI implementation
- File picker integration with Storage Access Framework

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Current version: **2.0.0**
- Major version bump due to significant code restructuring
- All changes are backward compatible in functionality
- No breaking changes to user-facing features
