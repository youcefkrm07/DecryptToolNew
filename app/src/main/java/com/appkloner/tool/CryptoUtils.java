package com.appkloner.tool;

import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;

public final class CryptoUtils {

    private static final String TAG = "CryptoUtils";

    private CryptoUtils() {}

    public static byte[] deriveKeyFromTimestamp(String baseKeyB64, String cloneTimestamp) {
        if (cloneTimestamp == null || cloneTimestamp.isEmpty()) {
            throw new IllegalArgumentException("Clone timestamp cannot be null or empty for key derivation.");
        }
        
        byte[] baseKeyBytes = Base64.decode(baseKeyB64, Base64.DEFAULT);
        String baseKeyStr = new String(baseKeyBytes, StandardCharsets.UTF_8);
        char[] baseKeyChars = baseKeyStr.toCharArray();
        char[] timestampChars = cloneTimestamp.toCharArray();

        int replaceLen = Math.min(baseKeyChars.length, timestampChars.length);

        for (int i = 0; i < replaceLen; i++) {
            baseKeyChars[i] = timestampChars[i];
        }
        String finalKeyString = new String(baseKeyChars);
        byte[] keyBytes = finalKeyString.getBytes(StandardCharsets.UTF_8);

        if (keyBytes.length != 32) {
             Log.w(TAG, "deriveKeyFromTimestamp: WARNING! Derived key byte length is " + keyBytes.length + ", but expected 32.");
        }
        return keyBytes;
    }

    public static String generateMd5Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(com.appkloner.tool.CryptoConstants.MD5_ALGORITHM);
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder(2 * digest.length);
        for (byte b : digest) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    public static byte[] deriveDynamicSettingsKey(String packageName) throws NoSuchAlgorithmException {
        if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("Package name cannot be null or empty for settings key derivation.");
        }
        String keyString = packageName + com.appkloner.tool.CryptoConstants.SETTINGS_KEY_SUFFIX;
        MessageDigest md = MessageDigest.getInstance(com.appkloner.tool.CryptoConstants.MD5_ALGORITHM);
        return md.digest(keyString.getBytes(StandardCharsets.UTF_8));
    }

    public static String generateSettingsFilename(String packageName, int index) throws NoSuchAlgorithmException {
         if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("Package name cannot be null or empty for settings filename generation.");
        }
        String nameString = packageName + com.appkloner.tool.CryptoConstants.SETTINGS_FILENAME_PREFIX + index;
        return generateMd5Hex(nameString);
     }

    public static String generateChainedPropertiesFilename(String currentKeyMd5) throws NoSuchAlgorithmException {
         if (currentKeyMd5 == null || currentKeyMd5.length() != 32) {
            throw new IllegalArgumentException("Invalid MD5 key for chained filename generation: " + currentKeyMd5);
         }
         String resourceSource = com.appkloner.tool.CryptoConstants.CHAINED_RESOURCE_PREFIX + currentKeyMd5;
         return generateMd5Hex(resourceSource);
     }

     public static byte[] getChainedSimpleCryptKeyBytes(String keyMd5HexString) {
         if (keyMd5HexString == null) {
           throw new IllegalArgumentException("keyMd5HexString cannot be null for getChainedSimpleCryptKeyBytes");
        }
        return keyMd5HexString.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] getAppDataXorKey(String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("Package name cannot be empty for XOR key generation.");
        }
        return packageName.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] getAppDataAesLegacyKey(String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("Package name cannot be empty for legacy AES key generation.");
        }
        byte[] keyBuffer = new byte[com.appkloner.tool.CryptoConstants.AES_BLOCK_SIZE];
        Arrays.fill(keyBuffer, (byte) '_');
        byte[] packageBytes = packageName.getBytes(StandardCharsets.UTF_8);
        int lengthToCopy = Math.min(packageBytes.length, keyBuffer.length);
        System.arraycopy(packageBytes, 0, keyBuffer, 0, lengthToCopy);
        return keyBuffer;
    }

    private static SecretKeySpec prepareAesKeySpec(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("AES key bytes cannot be null or empty.");
        }
        
        if (keyBytes.length == 32 || keyBytes.length == 24 || keyBytes.length == 16) {
            return new SecretKeySpec(keyBytes, com.appkloner.tool.CryptoConstants.AES_ALGORITHM);
        } else {
            throw new IllegalArgumentException("Invalid AES key length: " + keyBytes.length + ". Expected 16, 24, or 32 bytes.");
        }
    }

    private static byte[] decryptAesEcb(byte[] encryptedBytes, byte[] keyBytes, String transformation) {
        if (encryptedBytes == null || encryptedBytes.length == 0) return encryptedBytes;
        if (keyBytes == null || keyBytes.length == 0) return null;
        try {
            SecretKeySpec secretKey = prepareAesKeySpec(keyBytes);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(encryptedBytes);
        } catch (BadPaddingException e) {
            Log.e(TAG, "AES Decryption Failed (" + transformation + ") - BadPaddingException. Wrong key or padding scheme. Msg: " + e.getMessage());
            return null;
        } catch (Exception e) {
            Log.e(TAG, "AES Decryption Failed (" + transformation + ") - Unexpected exception.", e);
            return null;
        }
    }

    public static byte[] decryptAesEcbPkcs7(byte[] encryptedBytes, byte[] keyBytes) {
        return decryptAesEcb(encryptedBytes, keyBytes, CryptoConstants.AES_TRANSFORMATION_PKCS7);
    }
    
    public static byte[] decryptAesEcbPkcs5(byte[] encryptedBytes, byte[] keyBytes) {
        return decryptAesEcb(encryptedBytes, keyBytes, CryptoConstants.AES_TRANSFORMATION_PKCS5);
    }

    public static String decryptAesEcbPkcs7Base64(String encryptedBase64, byte[] keyBytes) {
        if (encryptedBase64 == null || encryptedBase64.isEmpty()) return null;
        try {
            byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
            byte[] decryptedBytes = decryptAesEcbPkcs7(encryptedBytes, keyBytes);
            return (decryptedBytes != null) ? new String(decryptedBytes, StandardCharsets.UTF_8) : null;
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Base64 decode failed: " + e.getMessage(), e);
            return null;
        }
     }
    
    private static byte[] encryptAesEcb(byte[] plainBytes, byte[] keyBytes, String transformation) {
        if (plainBytes == null) return null;
        if (keyBytes == null || keyBytes.length == 0) return null;
        try {
            SecretKeySpec secretKey = prepareAesKeySpec(keyBytes);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plainBytes);
        } catch (Exception e) {
            Log.e(TAG, "AES Encryption error (" + transformation + ")", e);
            return null;
        }
    }

    public static byte[] encryptAesEcbPkcs7(byte[] plainBytes, byte[] keyBytes) {
        return encryptAesEcb(plainBytes, keyBytes, CryptoConstants.AES_TRANSFORMATION_PKCS7);
    }
    
    public static byte[] encryptAesEcbPkcs5(byte[] plainBytes, byte[] keyBytes) {
        return encryptAesEcb(plainBytes, keyBytes, CryptoConstants.AES_TRANSFORMATION_PKCS5);
    }

    public static String encryptAesEcbPkcs7ToBase64(String plainText, byte[] keyBytes) {
         if (plainText == null) return null;
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encryptAesEcbPkcs7(plainBytes, keyBytes);
        return (encryptedBytes != null) ? Base64.encodeToString(encryptedBytes, Base64.NO_WRAP) : null;
    }

    public static byte[] performXor(byte[] data, byte[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("XOR key cannot be null or empty.");
        }
        if (data == null) return null;
        if (data.length == 0) return new byte[0];

        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        if (bytes.length == 0) return "empty_byte_array";
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }
    
    public static boolean isValidDexHeader(byte[] data) {
        if (data == null || data.length < 8) return false;
        return data[0] == (byte)'d' && data[1] == (byte)'e' && data[2] == (byte)'x' && data[3] == (byte)'\n' && data[7] == (byte)0x00;
    }
    
    /**
     * Decrypts old version strings.properties file using hardcoded AES key with PKCS5 padding.
     * This is the legacy method for decrypting strings.properties files.
     * 
     * @param encryptedData The encrypted strings.properties data
     * @return Decrypted data as byte array, or null if decryption fails
     */
    public static byte[] decryptOldStringsProperties(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            Log.w(TAG, "decryptOldStringsProperties: Input data is null or empty");
            return encryptedData;
        }
        
        Log.i(TAG, "Decrypting old version strings.properties with hardcoded key");
        
        // Decode the hardcoded 32-byte AES-256 key
        byte[] keyBytes = Base64.decode(CryptoConstants.OLD_STRINGS_PROPERTIES_KEY_B64, Base64.DEFAULT);
        
        Log.d(TAG, "Using key (hex): " + bytesToHex(keyBytes));
        Log.d(TAG, "Input size: " + encryptedData.length + " bytes");
        
        // Decrypt using AES-ECB with PKCS5 padding
        byte[] decryptedData = decryptAesEcbPkcs5(encryptedData, keyBytes);
        
        if (decryptedData != null) {
            Log.i(TAG, "Old strings.properties decryption successful. Output size: " + decryptedData.length);
        } else {
            Log.e(TAG, "Old strings.properties decryption failed");
        }
        
        return decryptedData;
    }
}