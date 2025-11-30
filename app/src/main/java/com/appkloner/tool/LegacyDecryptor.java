package com.appkloner.tool;

import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Legacy decryption methods for older AppCloner versions.
 * 
 * This class provides backward compatibility for decrypting files
 * from older AppCloner versions that used different encryption schemes.
 */
public final class LegacyDecryptor {
    
    private static final String TAG = "LegacyDecryptor";
    
    // Legacy hardcoded 32-byte key (256-bit AES) for old strings.properties
    private static final String LEGACY_PROPERTIES_KEY_B64 = "Q29GbnBTNnV4S2pkZklPeHZhWHlLNGJ5QlBTMVdjZFU=";
    
    private LegacyDecryptor() {} // Prevent instantiation
    
    /**
     * Decrypts strings.properties files from old AppCloner versions.
     * 
     * This method uses AES-ECB with PKCS5 padding and a hardcoded key
     * to decrypt strings.properties files from older AppCloner versions.
     * 
     * @param encryptedData The encrypted properties file content
     * @return Decrypted content as byte array, or null if decryption fails
     */
    public static byte[] decryptLegacyStringsProperties(byte[] encryptedData) {
        Log.i(TAG, "Attempting legacy strings.properties decryption");
        
        if (encryptedData == null || encryptedData.length == 0) {
            Log.w(TAG, "Input data is null or empty");
            return null;
        }
        
        try {
            // Decode the hardcoded base64 key
            byte[] keyBytes = Base64.decode(LEGACY_PROPERTIES_KEY_B64, Base64.DEFAULT);
            
            Log.d(TAG, "Using legacy key for strings.properties");
            Log.d(TAG, "Encrypted data size: " + encryptedData.length + " bytes");
            
            // Decrypt using AES-ECB with PKCS5 padding
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, CryptoConstants.AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CryptoConstants.AES_TRANSFORMATION_PKCS5);
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            
            byte[] decryptedData = cipher.doFinal(encryptedData);
            
            Log.i(TAG, "Legacy strings.properties decryption successful: " 
                    + decryptedData.length + " bytes");
            
            return decryptedData;
            
        } catch (javax.crypto.BadPaddingException e) {
            Log.e(TAG, "Legacy decryption failed - Bad padding. " +
                    "Data may not be encrypted with legacy key or is corrupted.", e);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Legacy decryption failed: " + e.getClass().getSimpleName() 
                    + " - " + e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Attempts to decrypt and parse legacy strings.properties file.
     * 
     * @param encryptedData The encrypted properties file content
     * @return Decrypted content as UTF-8 string, or null if decryption fails
     */
    public static String decryptLegacyStringsPropertiesToString(byte[] encryptedData) {
        byte[] decrypted = decryptLegacyStringsProperties(encryptedData);
        
        if (decrypted == null) {
            return null;
        }
        
        try {
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e(TAG, "Failed to convert decrypted data to UTF-8 string", e);
            return null;
        }
    }
    
    /**
     * Checks if data appears to be a valid properties file format.
     * 
     * @param data Decrypted data to check
     * @return true if data looks like properties format, false otherwise
     */
    public static boolean isValidPropertiesFormat(byte[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        
        try {
            String content = new String(data, StandardCharsets.UTF_8);
            // Basic heuristic: properties files typically contain '=' or ':' for key-value pairs
            return content.contains("=") || content.contains(":");
        } catch (Exception e) {
            return false;
        }
    }
}
