# AppCloner Tool - Architecture Overview

## Project Structure

```
app/src/main/java/com/appkloner/tool/
├── MainActivity.java              # Main activity & UI orchestration
├── DataMode.java                  # Enum: Data type modes
├── OperationMode.java             # Enum: Encrypt/Decrypt operations
├── SavableContent.java            # Data container with metadata
├── CryptoConstants.java           # Centralized crypto constants
├── CryptoUtils.java               # Modern crypto operations
├── PropertiesParser.java          # Properties file parsing
└── LegacyDecryptor.java          # Legacy format support

app/src/main/res/layout/
└── activity_main.xml              # UI layout with Material Design
```

## Class Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          MainActivity                            │
├─────────────────────────────────────────────────────────────────┤
│ - UI Components Management                                       │
│ - Activity Result Launchers                                      │
│ - File Selection Handlers                                        │
│ - Operation Orchestration                                        │
└──────────────┬──────────────────────────────────────────────────┘
               │
               │ uses
               ├──────────────────┐
               │                  │
               ↓                  ↓
    ┌──────────────────┐   ┌──────────────────┐
    │   CryptoUtils    │   │ LegacyDecryptor  │
    ├──────────────────┤   ├──────────────────┤
    │ + deriveKey()    │   │ + decryptLegacy()│
    │ + encryptAES()   │   │ + validateProps()│
    │ + decryptAES()   │   └──────────────────┘
    │ + performXOR()   │
    │ + generateMD5()  │
    └────────┬─────────┘
             │
             │ uses
             ↓
    ┌──────────────────┐
    │ CryptoConstants  │
    ├──────────────────┤
    │ + Base Keys      │
    │ + Algorithms     │
    │ + Prefixes       │
    │ + Block Sizes    │
    └──────────────────┘

    ┌──────────────────┐
    │PropertiesParser  │
    ├──────────────────┤
    │ + parseProps()   │
    │ + formatProps()  │
    └──────────────────┘

    ┌──────────────────┐        ┌──────────────────┐
    │   DataMode       │        │  OperationMode   │
    ├──────────────────┤        ├──────────────────┤
    │ • TIMESTAMP_DAT  │        │ • DECRYPT        │
    │ • CHAINED_PROPS  │        │ • ENCRYPT        │
    │ • CLONE_SETTINGS │        └──────────────────┘
    │ • APP_DATA       │
    │ • LEGACY_PROPS   │
    └──────────────────┘

    ┌──────────────────┐
    │ SavableContent   │
    ├──────────────────┤
    │ + data: Object   │
    │ + targetMode     │
    │ + operation      │
    │ + packageName    │
    │ + inputFilename  │
    └──────────────────┘
```

## Data Flow

### Decryption Flow

```
User Interaction
    ↓
Select APK File
    ↓
Extract Metadata (Package, Timestamp)
    ↓
Select Data Mode (Tab)
    ↓
Click "Process"
    ↓
MainActivity.startProcess()
    ↓
    ├─→ TIMESTAMP_DAT ──→ decryptTimestampDatFromApk()
    │                      ├─→ Find entry in APK
    │                      ├─→ CryptoUtils.deriveKeyFromTimestamp()
    │                      ├─→ CryptoUtils.decryptAesEcbPkcs5()
    │                      └─→ Validate DEX header
    │
    ├─→ CHAINED_PROPS ──→ decryptChainedPropertiesFromApk()
    │                      ├─→ Generate initial MD5 key
    │                      ├─→ Loop through chain (max 50)
    │                      │   ├─→ Find file by MD5 name
    │                      │   ├─→ Decrypt with key
    │                      │   ├─→ Parse properties
    │                      │   └─→ Use filename as next key
    │                      └─→ Combine all properties
    │
    ├─→ CLONE_SETTINGS ──→ decryptCloneSettingsFromApk()
    │                      ├─→ Derive dynamic key from package
    │                      ├─→ Find and read all parts (0, 1, 2...)
    │                      ├─→ Concatenate Base64 chunks
    │                      ├─→ CryptoUtils.decryptAesEcbPkcs7Base64()
    │                      └─→ Return JSON string
    │
    ├─→ APP_DATA ──────→ decryptAppDataFromApk()
    │                      ├─→ Find .app_data file
    │                      ├─→ Try XOR decryption first
    │                      ├─→ If fails, try legacy AES
    │                      └─→ Validate ZIP format
    │
    └─→ LEGACY_PROPS ──→ decryptLegacyStringsPropertiesFromApk()
                          ├─→ Find strings.properties
                          ├─→ LegacyDecryptor.decryptLegacy()
                          ├─→ Validate properties format
                          └─→ Return decrypted bytes
    ↓
Create SavableContent
    ↓
Update UI (Enable Save Button)
    ↓
User Clicks "Save"
    ↓
Generate Filename
    ↓
Save to Storage
```

### Encryption Flow

```
User Interaction
    ↓
Select APK (for metadata)
    ↓
Select Data Mode
    ↓
Switch to "Encrypt"
    ↓
Select Input File
    ↓
[Optional] Select Output Directory (for multi-file modes)
    ↓
Click "Process"
    ↓
MainActivity.performEncryption()
    ↓
    ├─→ TIMESTAMP_DAT ──→ encryptTimestampDatFile()
    │                      ├─→ Read plain DEX file
    │                      ├─→ Derive key from timestamp
    │                      ├─→ CryptoUtils.encryptAesEcbPkcs5()
    │                      └─→ Return encrypted .dat
    │
    ├─→ CHAINED_PROPS ──→ encryptChainedProperties()
    │                      ├─→ Parse input properties
    │                      ├─→ Split into 25 chunks
    │                      ├─→ Generate initial MD5 key
    │                      ├─→ For each chunk:
    │                      │   ├─→ Format properties
    │                      │   ├─→ Encrypt with current key
    │                      │   ├─→ Generate filename from key MD5
    │                      │   ├─→ Save to output directory
    │                      │   └─→ Use filename as next key
    │                      └─→ Signal completion
    │
    ├─→ CLONE_SETTINGS ──→ encryptCloneSettings()
    │                      ├─→ Read JSON input
    │                      ├─→ Derive dynamic key
    │                      ├─→ Encrypt to Base64
    │                      ├─→ Calculate chunk count (dynamic)
    │                      ├─→ Split into chunks
    │                      ├─→ Save each chunk with MD5 filename
    │                      └─→ Signal completion
    │
    ├─→ APP_DATA ──────→ encryptAppData()
    │                      ├─→ Read ZIP file
    │                      ├─→ Validate ZIP format
    │                      ├─→ Generate XOR key from package
    │                      ├─→ CryptoUtils.performXOR()
    │                      └─→ Return encrypted .app_data
    │
    └─→ LEGACY_PROPS ──→ [Not supported - decrypt only]
                          └─→ Show warning message
    ↓
[For single-file modes] Create SavableContent
    ↓
[For single-file modes] Update UI (Enable Save Button)
    ↓
[For multi-file modes] Files saved directly to directory
```

## Key Components

### MainActivity Responsibilities
1. **UI Management**
   - Initialize views
   - Handle user interactions
   - Update UI state
   - Display progress and logs

2. **File Operations**
   - APK selection and parsing
   - File reading (URI-based)
   - File saving (SAF - Storage Access Framework)
   - Temporary file management

3. **Operation Orchestration**
   - Coordinate encryption/decryption flows
   - Manage background tasks (ExecutorService)
   - Handle result callbacks
   - Error handling and logging

### CryptoUtils Responsibilities
1. **Key Derivation**
   - Timestamp-based key generation
   - MD5 hash generation
   - Dynamic key derivation

2. **Encryption/Decryption**
   - AES operations (PKCS5/PKCS7)
   - XOR operations
   - Base64 encoding/decoding

3. **Validation**
   - DEX header validation
   - Key length verification
   - Data integrity checks

### LegacyDecryptor Responsibilities
1. **Backward Compatibility**
   - Support old encryption schemes
   - Hardcoded key management
   - Legacy algorithm support

2. **Validation**
   - Properties format validation
   - Output verification

### PropertiesParser Responsibilities
1. **Parsing**
   - Multi-encoding support (UTF-8, ISO-8859-1)
   - Error-tolerant parsing
   - Key-value extraction

2. **Formatting**
   - Sorted output generation
   - Proper escaping
   - Timestamp comments

## Security Considerations

### Key Management
- Keys derived from metadata (timestamp, package name)
- Legacy keys hardcoded (for backward compatibility only)
- No key storage on device

### Encryption Algorithms
- AES-256 for modern formats
- XOR for simple obfuscation
- ECB mode used (per AppCloner specification)

### File Access
- Storage Access Framework (SAF) for secure file access
- Temporary files cleaned up on activity destroy
- Persistent URI permissions managed properly

## Threading Model

```
┌──────────────────────┐
│   Main Thread        │  ← UI Updates, User Interactions
└──────┬───────────────┘
       │
       │ Posts to
       ↓
┌──────────────────────┐
│ Background Thread    │  ← Crypto Operations, File I/O
│ (ExecutorService)    │
└──────┬───────────────┘
       │
       │ Callbacks via Handler
       ↓
┌──────────────────────┐
│   Main Thread        │  ← Update UI with results
└──────────────────────┘
```

## Extension Points

### Adding New Data Mode
1. Add enum value to `DataMode.java`
2. Add case to `onTabSelected()` in MainActivity
3. Add decrypt method `decryptNewModeFromApk()`
4. Add encrypt method `encryptNewMode()` (if applicable)
5. Update `generateSuggestedFilename()` switch
6. Add tab item to `activity_main.xml`

### Adding New Encryption Algorithm
1. Add constants to `CryptoConstants.java`
2. Add utility methods to `CryptoUtils.java`
3. Update relevant encrypt/decrypt methods
4. Add validation logic if needed

## Testing Strategy

### Unit Tests (Recommended)
- CryptoUtils methods with known inputs/outputs
- PropertiesParser with various encodings
- LegacyDecryptor with sample encrypted data
- Key derivation algorithms

### Integration Tests (Recommended)
- Full encrypt/decrypt cycle for each mode
- APK parsing and metadata extraction
- File I/O operations
- Error handling scenarios

### UI Tests (Recommended)
- Tab selection
- File picker flows
- Progress indication
- Error message display

## Performance Considerations

### Optimization Strategies
- Background processing for crypto operations
- Streaming for large files (where possible)
- Efficient buffer sizes (8KB)
- Lazy initialization of heavy objects

### Memory Management
- ByteArrayOutputStream with capacity hints
- Proper stream closing (try-with-resources)
- Temporary file cleanup
- Avoiding unnecessary data copies

## Conclusion

This architecture provides:
- ✅ Clear separation of concerns
- ✅ Easy extensibility for new modes
- ✅ Backward compatibility support
- ✅ Proper error handling
- ✅ Secure file operations
- ✅ Maintainable codebase
