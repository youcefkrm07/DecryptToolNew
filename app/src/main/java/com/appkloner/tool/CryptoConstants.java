package com.appkloner.tool;

import java.nio.charset.StandardCharsets;

public final class CryptoConstants {

    private CryptoConstants() {} // Prevent instantiation

    // Key Derivation / Generation Constants
    public static final String BASE_KEY_B64_FOR_TIMESTAMP_DAT = "Q29GbnBTNnV4S2pkZklPeHZhWHlLNGJ5QlBTMVdjZFU="; // New/Kotlin key
    public static final String ORIGINAL_SMALI_BASE_KEY_B64 = "aE5rNEZUUnB2QXl0R2V3ZFBYZjNtWlVRZzc2S3VDQjk="; // Old/Smali key
    
    // Old version key for strings.properties (hardcoded 32-byte key)
    public static final String OLD_STRINGS_PROPERTIES_KEY_B64 = "Q29GbnBTNnV4S2pkZklPeHZhWHlLNGJ5QlBTMVdjZFU="; // Same as timestamp.dat key

    public static final String CHAINED_KEY_PREFIX = "584BEF6DF3297F91623E2DE659BF8D2F";
    public static final String CHAINED_RESOURCE_PREFIX = "A8F5F167F44F4964E6C998DEE827110C";
    
    // Chained properties constants
    public static final int CHAINED_MAX_DEPTH = 50; // Maximum chain depth for decryption
    public static final int CHAINED_ENCRYPTION_CHUNK_COUNT = 25; // Target chunk count for encryption
    public static final String SETTINGS_KEY_SUFFIX = "/I am the one who knocks!";
    public static final String SETTINGS_FILENAME_PREFIX = "I'll be back.";
    public static final String SETTINGS_FIXED_KEY_STR = "UYGy723!Po-efjve"; // Legacy?
    public static final byte[] SETTINGS_FIXED_KEY_BYTES = SETTINGS_FIXED_KEY_STR.getBytes(StandardCharsets.UTF_8);

    // Algorithm Constants
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_TRANSFORMATION_PKCS7 = "AES/ECB/PKCS7Padding"; // For settings, chained props
    public static final String AES_TRANSFORMATION_PKCS5 = "AES/ECB/PKCS5Padding"; // For timestamp-based .dat and single properties
    public static final String MD5_ALGORITHM = "MD5";
    public static final int AES_BLOCK_SIZE = 16; // Bytes

    // Metadata Key for APK Parsing
    public static final String META_DATA_KEY_CLONE_TIMESTAMP = "com.applisto.appcloner.cloneTimestamp";
}