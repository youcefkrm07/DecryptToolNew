package com.appkloner.tool;

/**
 * MainActivity for AppCloner Tool
 * 
 * This application allows users to encrypt and decrypt various data formats used by AppCloner.
 * Supported operations include:
 * - Timestamp-based DAT files (app_cloner.dat)
 * - Chained properties files
 * - Clone settings (JSON configuration)
 * - App data (ZIP archives)
 * - Legacy strings.properties files
 * 
 * @author AppCloner Tool Team
 * @version 2.0
 */

// --- Imports ---
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.documentfile.provider.DocumentFile;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.text.method.ScrollingMovementMethod;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.tabs.TabLayout;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = "AppClonerToolJava";

    // UI Elements
    private Button btnSelectApkOrDir;
    private TextView tvSelectedPathLabel;
    private TextView tvSelectedPathValue;
    private TextView tvPackageName;
    private TextView tvTimestamp;
    private RadioGroup radioGroupOperation;
    private RadioButton radioDecrypt;
    private RadioButton radioEncrypt;

    // Replaced RadioGroup with TabLayout
    private TabLayout tabLayoutMode;

    private TextView tvEncryptionInputLabel;
    private Button btnSelectInputFile;
    private TextView tvSelectedInputFilePath;
    private Button btnSelectEncryptOutputDir;
    private TextView tvSelectedEncryptOutputDirPath;
    private LinearLayout layoutEncryptionInputs;
    private Button btnProcess;
    private Button btnSaveFile;
    private ProgressBar progressBar;
    private TextView tvLogOutput;

    // State Variables
    private Uri selectedApkUri;
    private String tempApkPath = null;
    private Uri selectedInputFileUri;
    private Uri selectedEncryptOutputDirUri;
    private String extractedPackageName;
    private Long extractedTimestamp;
    private OperationMode currentOperation = OperationMode.DECRYPT;
    private DataMode currentDataMode = DataMode.TIMESTAMP_DAT; // Default to first tab
    private SavableContent currentSavableContent = null;
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final Handler mainThreadHandler = new Handler(Looper.getMainLooper());

    // Activity Result Launchers
    private ActivityResultLauncher<String[]> apkPickerLauncher;
    private ActivityResultLauncher<String[]> inputFilePickerLauncher;
    private ActivityResultLauncher<Uri> encryptOutputDirPickerLauncher;
    private ActivityResultLauncher<String> saveFileLauncher;


    // ========================================================================
    // INNER CLASSES (DataMode, OperationMode, SavableContent, CryptoConstants, CryptoUtils, PropertiesParser)
    // ========================================================================
     public enum DataMode { TIMESTAMP_DAT, CHAINED_PROPERTIES, CLONE_SETTINGS, APP_DATA }
     public enum OperationMode { DECRYPT, ENCRYPT }
    public static class SavableContent { public final Object data; public final MainActivity.DataMode targetMode; public final MainActivity.OperationMode operationPerformed; public final String packageName; public final String inputFilename; public SavableContent(Object data, MainActivity.DataMode targetMode, MainActivity.OperationMode operationPerformed, String packageName, String inputFilename) { if (data == null && !((targetMode == MainActivity.DataMode.CHAINED_PROPERTIES || targetMode == MainActivity.DataMode.CLONE_SETTINGS) && operationPerformed == MainActivity.OperationMode.ENCRYPT)) ; if (!(data instanceof String || data instanceof byte[] || data == null)) throw new IllegalArgumentException("Unsupported data type for SavableContent: " + data.getClass().getName()); this.data = data; this.targetMode = targetMode; this.operationPerformed = operationPerformed; this.packageName = packageName; this.inputFilename = inputFilename; } }
    public static final class CryptoConstants {
        private CryptoConstants() {}
        // Key for app_cloner.dat, aligned with the "correct" Kotlin version
        public static final String BASE_KEY_B64_FOR_TIMESTAMP_DAT = "Q29GbnBTNnV4S2pkZklPeHZhWHlLNGJ5QlBTMVdjZFU=";
        // Original keys for other modes (assuming they might use different base keys or logic)
        public static final String ORIGINAL_SMALI_BASE_KEY_B64 = "aE5rNEZUUnB2QXl0R2V3ZFBYZjNtWlVRZzc2S3VDQjk="; // For reference or other modes if needed

        public static final String CHAINED_KEY_PREFIX = "584BEF6DF3297F91623E2DE659BF8D2F";
        public static final String CHAINED_RESOURCE_PREFIX = "A8F5F167F44F4964E6C998DEE827110C";

        // Updated constants based on PHP source
        public static final int CHAINED_MAX_DEPTH = 50; // Updated to 50 to match PHP
        public static final int CHAINED_ENCRYPTION_CHUNK_COUNT = 25; // New constant for encryption chunk count

        public static final String SETTINGS_KEY_SUFFIX = "/I am the one who knocks!";
        public static final String SETTINGS_FILENAME_PREFIX = "I'll be back.";
        public static final String SETTINGS_FIXED_KEY_STR = "UYGy723!Po-efjve";
        public static final byte[] SETTINGS_FIXED_KEY_BYTES = SETTINGS_FIXED_KEY_STR.getBytes(StandardCharsets.UTF_8);
        public static final String AES_ALGORITHM = "AES";
        public static final String AES_TRANSFORMATION_PKCS7 = "AES/ECB/PKCS7Padding";
        public static final String AES_TRANSFORMATION_PKCS5 = "AES/ECB/PKCS5Padding"; // Added for .dat decryption
        public static final String MD5_ALGORITHM = "MD5";
        public static final int AES_BLOCK_SIZE = 16;
        public static final String META_DATA_KEY_CLONE_TIMESTAMP = "com.applisto.appcloner.cloneTimestamp";
    }
    public static final class CryptoUtils {
        private static final String TAG = "CryptoUtilsInner";
        private CryptoUtils() {}

        // Public method using the default (new) base key for timestamp derivation
        public static byte[] deriveKeyFromTimestamp(String cloneTimestamp) {
            return deriveKeyFromTimestampInternal(MainActivity.CryptoConstants.BASE_KEY_B64_FOR_TIMESTAMP_DAT, cloneTimestamp);
        }

        // Public method allowing to specify the base key for timestamp derivation
        public static byte[] deriveKeyFromTimestamp(String baseKeyB64, String cloneTimestamp) {
            return deriveKeyFromTimestampInternal(baseKeyB64, cloneTimestamp);
        }

        // Internal core logic for deriving key from timestamp and a given base key
        private static byte[] deriveKeyFromTimestampInternal(String baseKeyB64, String cloneTimestamp) {
            Log.i(TAG, "CryptoUtils.deriveKeyFromTimestampInternal BEGIN (Base B64: " + baseKeyB64 + ")");
            if (cloneTimestamp == null || cloneTimestamp.isEmpty()) {
                Log.e(TAG, "deriveKeyFromTimestampInternal: Clone timestamp null/empty.");
                throw new IllegalArgumentException("Clone timestamp null/empty for key derivation.");
            }
            Log.d(TAG, "deriveKeyFromTimestampInternal: Input cloneTimestamp string: '" + cloneTimestamp + "' (Len: " + cloneTimestamp.length() + ")");
            Log.d(TAG, "deriveKeyFromTimestampInternal: Using Base key B64: '" + baseKeyB64 + "'");

            byte[] baseKeyBytes = Base64.decode(baseKeyB64, Base64.DEFAULT); // Use the passed baseKeyB64
            String baseKeyStr = new String(baseKeyBytes, StandardCharsets.UTF_8);
            char[] baseKeyChars = baseKeyStr.toCharArray();

            char[] timestampChars = cloneTimestamp.toCharArray();
            Log.d(TAG, "deriveKeyFromTimestampInternal: Decoded Base key string: '" + baseKeyStr + "' (Len: " + baseKeyChars.length + "), Timestamp char[] len: " + timestampChars.length);

            int replaceLen = Math.min(baseKeyChars.length, timestampChars.length);
            Log.d(TAG, "deriveKeyFromTimestampInternal: Chars to overwrite in base key: " + replaceLen);

            for (int i = 0; i < replaceLen; i++) {
                baseKeyChars[i] = timestampChars[i];
            }
            String finalKeyString = new String(baseKeyChars);
            Log.d(TAG, "deriveKeyFromTimestampInternal: Final key string (after overlay): '" + finalKeyString + "' (Len: " + finalKeyString.length() + ")");

            byte[] keyBytes = finalKeyString.getBytes(StandardCharsets.UTF_8);
            Log.d(TAG, "deriveKeyFromTimestampInternal: Final derived key BYTES length: " + keyBytes.length);
            Log.d(TAG, "deriveKeyFromTimestampInternal: Derived key bytes (FULL HEX): " + bytesToHex(keyBytes));

            if (keyBytes.length != 32) {
                Log.w(TAG, "deriveKeyFromTimestampInternal: WARNING! Derived key byte length is " + keyBytes.length + ", expected 32. Non-ASCII chars in timestamp overlay or base key issue?");
            }
            Log.i(TAG, "CryptoUtils.deriveKeyFromTimestampInternal END");
            return keyBytes;
        }

        public static String generateMd5Hex(String input) throws NoSuchAlgorithmException { MessageDigest md = MessageDigest.getInstance(MainActivity.CryptoConstants.MD5_ALGORITHM); byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8)); StringBuilder sb = new StringBuilder(2*digest.length); for(byte b:digest){String hex=Integer.toHexString(0xff&b); if(hex.length()==1)sb.append('0'); sb.append(hex);} return sb.toString().toUpperCase(); }
        public static byte[] deriveDynamicSettingsKey(String pkg) throws NoSuchAlgorithmException { if(pkg==null||pkg.isEmpty())throw new IllegalArgumentException("Pkg null/empty for settings key"); String ks=pkg+MainActivity.CryptoConstants.SETTINGS_KEY_SUFFIX; MessageDigest md=MessageDigest.getInstance(MainActivity.CryptoConstants.MD5_ALGORITHM); return md.digest(ks.getBytes(StandardCharsets.UTF_8));}
        public static String generateSettingsFilename(String pkg, int i) throws NoSuchAlgorithmException { if(pkg==null||pkg.isEmpty())throw new IllegalArgumentException("Pkg null/empty for settings filename"); String ns=pkg+MainActivity.CryptoConstants.SETTINGS_FILENAME_PREFIX+i; return generateMd5Hex(ns);}
        public static String generateChainedPropertiesFilename(String ckm) throws NoSuchAlgorithmException { if(ckm==null||ckm.length()!=32)throw new IllegalArgumentException("Invalid MD5 for chained filename: "+ckm); String rs=MainActivity.CryptoConstants.CHAINED_RESOURCE_PREFIX+ckm; return generateMd5Hex(rs);}
        public static byte[] getChainedSimpleCryptKeyBytes(String kmh) { if(kmh==null||kmh.length()!=32)Log.w(TAG,"Chained key source MD5 not 32: "+(kmh!=null?kmh.length():"null")); if(kmh==null)throw new IllegalArgumentException("keyMd5HexString null"); return kmh.getBytes(StandardCharsets.UTF_8);} // This key is derived from an MD5 hex string, so it's ASCII.
        public static byte[] getAppDataXorKey(String pkg) { if(pkg==null||pkg.isEmpty())throw new IllegalArgumentException("Pkg empty for XOR key"); return pkg.getBytes(StandardCharsets.UTF_8);}
        public static byte[] getAppDataAesLegacyKey(String pkg) { if(pkg==null||pkg.isEmpty())throw new IllegalArgumentException("Pkg empty for legacy AES key"); byte[]kb=new byte[MainActivity.CryptoConstants.AES_BLOCK_SIZE]; Arrays.fill(kb,(byte)'_'); byte[]pb=pkg.getBytes(StandardCharsets.UTF_8); System.arraycopy(pb,0,kb,0,Math.min(pb.length,kb.length)); return kb;}

        private static SecretKeySpec prepareAesKeySpec(byte[] keyBytes) {
            Log.i(TAG, "CryptoUtils.prepareAesKeySpec BEGIN");
            if (keyBytes == null || keyBytes.length == 0) {
                Log.e(TAG, "prepareAesKeySpec: AES key bytes null/empty.");
                throw new IllegalArgumentException("AES key bytes null/empty.");
            }
            Log.d(TAG, "prepareAesKeySpec: Received keyBytes length: " + keyBytes.length + " (HEX): " + bytesToHex(keyBytes));
            byte[] finalKeyForSpec;
            if (keyBytes.length == 32) { // AES-256
                finalKeyForSpec = keyBytes;
                Log.d(TAG, "prepareAesKeySpec: Key is 32 bytes. Using directly for AES-256.");
            } else if (keyBytes.length == 24) { // AES-192
                finalKeyForSpec = keyBytes;
                Log.d(TAG, "prepareAesKeySpec: Key is 24 bytes. Using directly for AES-192.");
            } else if (keyBytes.length == 16) { // AES-128
                finalKeyForSpec = keyBytes;
                Log.d(TAG, "prepareAesKeySpec: Key is 16 bytes. Using directly for AES-128.");
            } else {
                Log.e(TAG, "prepareAesKeySpec: CRITICAL! Received key length is " + keyBytes.length + " bytes, not a standard AES key size (16, 24, or 32).");
                // For AppCloner's SimpleCrypt (used for chained properties), the key is an MD5 hex string (32 chars) converted to bytes (32 bytes).
                // For timestamp.dat, the derived key from "Q29G..." (32 chars) + timestamp overlay, converted to UTF-8 bytes, should also be 32 bytes.
                throw new IllegalArgumentException("Invalid AES key length: " + keyBytes.length + ". Expected 16, 24, or 32 bytes.");
            }
            Log.d(TAG, "prepareAesKeySpec: Final key for SecretKeySpec (HEX): " + bytesToHex(finalKeyForSpec) + " (Length: " + finalKeyForSpec.length + ")");
            SecretKeySpec spec = new SecretKeySpec(finalKeyForSpec, MainActivity.CryptoConstants.AES_ALGORITHM);
            Log.i(TAG, "CryptoUtils.prepareAesKeySpec END - SecretKeySpec created.");
            return spec;
        }

        // Generic AES Decryption method
        private static byte[] decryptAesEcb(byte[] encryptedBytes, byte[] keyBytes, String transformation) {
            Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") BEGIN");
            if (encryptedBytes == null || encryptedBytes.length == 0) {
                Log.w(TAG, "decryptAesEcb: Input encryptedBytes null/empty. Returning as is.");
                return encryptedBytes;
            }
            if (keyBytes == null || keyBytes.length == 0) {
                Log.e(TAG, "decryptAesEcb: Input keyBytes null/empty. Cannot decrypt. Returning null.");
                return null;
            }
            Log.d(TAG, "decryptAesEcb: Encrypted data length: " + encryptedBytes.length + ". Key (HEX from caller): " + bytesToHex(keyBytes));
            try {
                Log.d(TAG, "decryptAesEcb: Preparing SecretKeySpec...");
                SecretKeySpec secretKey = prepareAesKeySpec(keyBytes);
                if (secretKey == null || secretKey.getEncoded() == null) {
                     Log.e(TAG, "decryptAesEcb: prepareAesKeySpec returned null/invalid SecretKeySpec!"); return null;
                }
                Log.d(TAG, "decryptAesEcb: SecretKeySpec internal key (HEX): " + bytesToHex(secretKey.getEncoded()) + " (Len: " + secretKey.getEncoded().length + ", Algo: " + secretKey.getAlgorithm() + ")");
                Log.d(TAG, "decryptAesEcb: Cipher.getInstance with: '" + transformation + "'");
                Cipher cipher = Cipher.getInstance(transformation);
                Log.d(TAG, "decryptAesEcb: Cipher provider: " + cipher.getProvider().getName() + " (Version: " + cipher.getProvider().getVersion() + ")");

                Log.d(TAG, "decryptAesEcb: Initializing cipher DECRYPT_MODE...");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                Log.d(TAG, "decryptAesEcb: Cipher initialized. Block size: " + cipher.getBlockSize() + ". Performing doFinal...");
                byte[] decryptedData = cipher.doFinal(encryptedBytes);
                Log.i(TAG, "decryptAesEcb: Decryption successful. Decrypted length: " + (decryptedData != null ? decryptedData.length : "null"));
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - SUCCESS");
                return decryptedData;
            } catch (BadPaddingException e) {
                Log.e(TAG, "decryptAesEcb: FAIL (" + transformation + ") - BadPaddingException. Msg: " + e.getMessage());
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - BadPaddingException");
                return null;
            } catch (IllegalBlockSizeException e) {
                Log.e(TAG, "decryptAesEcb: FAIL (" + transformation + ") - IllegalBlockSizeException. Msg: " + e.getMessage(), e);
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - IllegalBlockSizeException");
                return null;
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "decryptAesEcb: FAIL (" + transformation + ") - NoSuchAlgorithmException. Msg: " + e.getMessage(), e);
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - NoSuchAlgorithmException");
                return null;
            } catch (NoSuchPaddingException e) {
                Log.e(TAG, "decryptAesEcb: FAIL (" + transformation + ") - NoSuchPaddingException. Msg: " + e.getMessage(), e);
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - NoSuchPaddingException");
                return null;
            } catch (InvalidKeyException e) {
                Log.e(TAG, "decryptAesEcb: FAIL (" + transformation + ") - InvalidKeyException. Msg: " + e.getMessage(), e);
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - InvalidKeyException");
                return null;
            } catch (Exception e) {
                Log.e(TAG, "decryptAesEcb: FAIL (" + transformation + ") - Unexpected generic crypto exception. Type: " + e.getClass().getName() + ", Msg: " + e.getMessage(), e);
                Log.i(TAG, "CryptoUtils.decryptAesEcb (" + transformation + ") END - Generic Exception");
                return null;
            }
        }

        public static byte[] decryptAesEcbPkcs7(byte[] encryptedBytes, byte[] keyBytes) {
            return decryptAesEcb(encryptedBytes, keyBytes, MainActivity.CryptoConstants.AES_TRANSFORMATION_PKCS7);
        }

        public static byte[] decryptAesEcbPkcs5(byte[] encryptedBytes, byte[] keyBytes) {
            return decryptAesEcb(encryptedBytes, keyBytes, MainActivity.CryptoConstants.AES_TRANSFORMATION_PKCS5);
        }

        public static String decryptAesEcbPkcs7Base64(String encB64, byte[] keyBytes) { if(encB64==null||encB64.isEmpty()){Log.w(TAG,"Base64 Decrypt (PKCS7): Input null/empty.");return null;} try{byte[]encBytes=Base64.decode(encB64,Base64.DEFAULT);byte[]decBytes=decryptAesEcbPkcs7(encBytes,keyBytes);return(decBytes!=null)?new String(decBytes,StandardCharsets.UTF_8):null;}catch(IllegalArgumentException e){Log.e(TAG,"Base64 decode failed: "+e.getMessage(),e);return null;}}

        // Generic AES Encryption method
        private static byte[] encryptAesEcb(byte[] plainBytes, byte[] keyBytes, String transformation) {
            Log.i(TAG, "CryptoUtils.encryptAesEcb (" + transformation + ") BEGIN");
            if(plainBytes==null){Log.w(TAG,"encryptAesEcb: Input plainBytes null.");return null;}
            if(keyBytes==null||keyBytes.length==0){Log.e(TAG,"encryptAesEcb: Key null/empty.");return null;}
            try{
                SecretKeySpec sk=prepareAesKeySpec(keyBytes);
                Cipher c=Cipher.getInstance(transformation);
                c.init(Cipher.ENCRYPT_MODE,sk);
                byte[] encryptedData = c.doFinal(plainBytes);
                Log.i(TAG, "CryptoUtils.encryptAesEcb (" + transformation + ") END - SUCCESS");
                return encryptedData;
            }catch(Exception e){Log.e(TAG,"encryptAesEcb ("+transformation+") error: "+e.getMessage()+" ("+e.getClass().getSimpleName()+")",e);return null;}
        }

        public static byte[] encryptAesEcbPkcs7(byte[] plainBytes, byte[] keyBytes) {
            return encryptAesEcb(plainBytes, keyBytes, MainActivity.CryptoConstants.AES_TRANSFORMATION_PKCS7);
        }
         public static byte[] encryptAesEcbPkcs5(byte[] plainBytes, byte[] keyBytes) {
            return encryptAesEcb(plainBytes, keyBytes, MainActivity.CryptoConstants.AES_TRANSFORMATION_PKCS5);
        }

        public static String encryptAesEcbPkcs7ToBase64(String plainText, byte[] keyBytes) { if(plainText==null){Log.w(TAG,"Base64 Encrypt (PKCS7): Input null.");return null;} try{byte[]pb=plainText.getBytes(StandardCharsets.UTF_8);byte[]eb=encryptAesEcbPkcs7(pb,keyBytes);return(eb!=null)?Base64.encodeToString(eb,Base64.NO_WRAP):null;}catch(Exception e){Log.e(TAG,"Base64 Encrypt (PKCS7) error: "+e.getMessage(),e);return null;}}
        public static byte[] performXor(byte[] data, byte[] key) { if(key==null||key.length==0)throw new IllegalArgumentException("XOR key null/empty."); if(data==null)return null;if(data.length==0)return new byte[0]; byte[]r=new byte[data.length];for(int i=0;i<data.length;i++)r[i]=(byte)(data[i]^key[i%key.length]);return r;}
        private static String bytesToHex(byte[] bytes) { if(bytes==null)return"null";if(bytes.length==0)return"empty_byte_array";StringBuilder sb=new StringBuilder(2*bytes.length);for(byte b:bytes){String hex=Integer.toHexString(0xff&b);if(hex.length()==1)sb.append('0');sb.append(hex);}return sb.toString().toUpperCase();}

        // Helper to check for DEX magic header
        public static boolean isValidDexHeader(byte[] data) {
            if (data == null || data.length < 8) return false;
            // Checks for "dex\n" followed by version like "035\0" or "036\0"
            return data[0] == (byte)'d' && data[1] == (byte)'e' && data[2] == (byte)'x' && data[3] == (byte)'\n' && data[7] == (byte)0x00;
        }
    }
    public static final class PropertiesParser { private static final String TAG="PropertiesParserInner";private PropertiesParser(){} public static Map<String,String>parseProperties(byte[]d){Map<String,String>m=new LinkedHashMap<>();if(d==null||d.length==0)return m;Properties p=new Properties();BufferedReader r=null;boolean pu=false;try{r=new BufferedReader(new InputStreamReader(new ByteArrayInputStream(d),StandardCharsets.UTF_8));p.load(r);if(!p.isEmpty())pu=true;}catch(Exception ig){p.clear();}finally{if(r!=null)try{r.close();r=null;}catch(IOException ig){}}if(!pu&&d.length>0){p.clear();try{r=new BufferedReader(new InputStreamReader(new ByteArrayInputStream(d),StandardCharsets.ISO_8859_1));p.load(r);}catch(Exception ig){}finally{if(r!=null)try{r.close();}catch(IOException ig){}}}for(Map.Entry<Object,Object>e:p.entrySet())if(e.getKey()instanceof String&&e.getValue()instanceof String)m.put((String)e.getKey(),(String)e.getValue());else if(e.getKey()!=null&&e.getValue()!=null)m.put(e.getKey().toString(),e.getValue().toString());return m;} public static String formatProperties(Map<String,String>m){Properties sp=new Properties(){@Override public synchronized Enumeration<Object>keys(){return Collections.enumeration(super.keySet().stream().map(Object::toString).sorted().collect(Collectors.toList()));}};sp.putAll(m);String ts=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z",Locale.US).format(new Date());String c="#Props - "+ts+"\n#Total: "+m.size();try(ByteArrayOutputStream bs=new ByteArrayOutputStream();OutputStreamWriter o=new OutputStreamWriter(bs,StandardCharsets.UTF_8)){sp.store(o,c);return bs.toString(StandardCharsets.UTF_8.name());}catch(IOException e){StringBuilder sb=new StringBuilder();sb.append(c).append("\n\n");m.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry->sb.append(entry.getKey()).append(" = ").append(entry.getValue()).append("\n"));return sb.toString();}}}
    // ========================================================================
    // END: Consolidated Inner Classes/Enums
    // ========================================================================

    @Override protected void onCreate(Bundle s){super.onCreate(s);setContentView(R.layout.activity_main);initializeViews();registerLaunchers();setupListeners();updateUiState();}
    @Override protected void onDestroy(){super.onDestroy();if(executorService!=null&&!executorService.isShutdown())executorService.shutdownNow();deleteTempApkFile();Log.d(TAG,"onDestroy finished.");}
    private void initializeViews(){
        btnSelectApkOrDir=findViewById(R.id.btnSelectApk);
        tvSelectedPathLabel=findViewById(R.id.tvPathLabel);
        tvSelectedPathValue=findViewById(R.id.tvSelectedApkPath);
        tvPackageName=findViewById(R.id.tvPackageName);
        tvTimestamp=findViewById(R.id.tvTimestamp);
        tvTimestamp.setTextIsSelectable(true);
        radioGroupOperation=findViewById(R.id.radioGroupOperation);
        radioDecrypt=findViewById(R.id.radioDecrypt);
        radioEncrypt=findViewById(R.id.radioEncrypt);

        tabLayoutMode=findViewById(R.id.tabLayoutMode);

        tvEncryptionInputLabel=findViewById(R.id.tvEncryptionInputLabel);
        btnSelectInputFile=findViewById(R.id.btnSelectInputFile);
        tvSelectedInputFilePath=findViewById(R.id.tvSelectedInputFilePath);
        btnSelectEncryptOutputDir=findViewById(R.id.btnSelectDirectory);
        tvSelectedEncryptOutputDirPath=findViewById(R.id.tvSelectedDirectoryPath);
        layoutEncryptionInputs=findViewById(R.id.layoutEncryptionInputs);
        btnProcess=findViewById(R.id.btnProcess);
        btnSaveFile=findViewById(R.id.btnSaveFile);
        progressBar=findViewById(R.id.progressBar);
        tvLogOutput=findViewById(R.id.tvLogOutput);
        tvLogOutput.setMovementMethod(new ScrollingMovementMethod());
        clearLog();
        appendLog("AppCloner Tool Initialized.");
    }
    private void registerLaunchers(){apkPickerLauncher=registerForActivityResult(new ActivityResultContracts.OpenDocument(),u->{if(u!=null)handleSelectedApk(u);else{Toast.makeText(this,"APK selection cancelled.",Toast.LENGTH_SHORT).show();appendLog("APK selection cancelled.");}});inputFilePickerLauncher=registerForActivityResult(new ActivityResultContracts.OpenDocument(),u->{if(u!=null){selectedInputFileUri=u;try{getContentResolver().takePersistableUriPermission(u,Intent.FLAG_GRANT_READ_URI_PERMISSION);tvSelectedInputFilePath.setText("Input File: "+getFileNameFromUri(u));appendLog("Selected input file: "+getFileNameFromUri(u));}catch(SecurityException e){Log.e(TAG,"Perm denial for input file: "+u,e);Toast.makeText(this,"Failed perm for input file.",Toast.LENGTH_LONG).show();selectedInputFileUri=null;}}else{Toast.makeText(this,"Input file selection cancelled.",Toast.LENGTH_SHORT).show();appendLog("Input file selection cancelled.");}updateUiState();});encryptOutputDirPickerLauncher=registerForActivityResult(new ActivityResultContracts.OpenDocumentTree(),u->{if(u!=null){selectedEncryptOutputDirUri=u;try{getContentResolver().takePersistableUriPermission(u,Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION);tvSelectedEncryptOutputDirPath.setText("Output Dir: "+getDirNameFromTreeUri(u));appendLog("Selected encrypt output dir: "+getDirNameFromTreeUri(u));}catch(SecurityException e){Log.e(TAG,"Perm denial for encrypt out dir: "+u,e);Toast.makeText(this,"Failed perm for out dir.",Toast.LENGTH_LONG).show();selectedEncryptOutputDirUri=null;}}else{Toast.makeText(this,"Encrypt out dir selection cancelled.",Toast.LENGTH_SHORT).show();appendLog("Encrypt out dir selection cancelled.");}updateUiState();});saveFileLauncher=registerForActivityResult(new ActivityResultContracts.CreateDocument("*/*"),u->{Log.d(TAG,"Save File Launcher Callback.");if(u!=null){Log.d(TAG,"Target URI for saving: "+u.toString());final SavableContent c=currentSavableContent;if(c!=null)saveContentToFile(c,u);else{Log.e(TAG,"currentSavableContent NULL in save cb!");Toast.makeText(this,"Error: No content to save.",Toast.LENGTH_LONG).show();appendLog("❌ Error: Content to save was null.");}}else{Log.w(TAG,"Save File Launcher NULL URI.");Toast.makeText(this,"File saving cancelled.",Toast.LENGTH_SHORT).show();appendLog("File saving cancelled.");}});}

    private void setupListeners(){
        btnSelectApkOrDir.setOnClickListener(v->{clearPersistedPermissions();clearSourceData(true);appendLog("Please select cloned APK...");apkPickerLauncher.launch(new String[]{"application/vnd.android.package-archive"});});
        btnSelectInputFile.setOnClickListener(v->{clearPersistedPermissions();appendLog("Please select input file for encrypt...");inputFilePickerLauncher.launch(new String[]{"*/*"});});
        btnSelectEncryptOutputDir.setOnClickListener(v->{clearPersistedPermissions();appendLog("Please select out dir for encrypted files...");encryptOutputDirPickerLauncher.launch(null);});

        radioGroupOperation.setOnCheckedChangeListener((g,id)->{
            currentOperation=(id==R.id.radioEncrypt)?MainActivity.OperationMode.ENCRYPT:MainActivity.OperationMode.DECRYPT;
            appendLog("Op mode: "+currentOperation.name());
            if(currentOperation==MainActivity.OperationMode.DECRYPT){
                selectedInputFileUri=null;
                selectedEncryptOutputDirUri=null;
                tvSelectedInputFilePath.setText("Input File: (None)");
                tvSelectedEncryptOutputDirPath.setText("Output Dir: (None)");
            }
            currentSavableContent=null;
            updateUiState();
        });

        tabLayoutMode.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override
            public void onTabSelected(TabLayout.Tab tab) {
                switch (tab.getPosition()) {
                    case 0: currentDataMode = DataMode.TIMESTAMP_DAT; break;
                    case 1: currentDataMode = DataMode.CHAINED_PROPERTIES; break;
                    case 2: currentDataMode = DataMode.CLONE_SETTINGS; break;
                    case 3: currentDataMode = DataMode.APP_DATA; break;
                    case 4: currentDataMode = DataMode.LEGACY_STRINGS_PROPERTIES; break;
                    default: 
                        appendLog("Unknown tab position: " + tab.getPosition());
                        currentDataMode = DataMode.TIMESTAMP_DAT;
                        break;
                }
                appendLog("Data mode: " + currentDataMode.name());
                currentSavableContent = null;
                updateUiState();
            }
            @Override public void onTabUnselected(TabLayout.Tab tab) {}
            @Override public void onTabReselected(TabLayout.Tab tab) {}
        });

        tvTimestamp.setOnLongClickListener(v->{if(extractedTimestamp!=null){String tsV=String.valueOf(extractedTimestamp);ClipboardManager cb=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);if(cb!=null){cb.setPrimaryClip(ClipData.newPlainText("Clone Timestamp",tsV));Toast.makeText(MainActivity.this,"Timestamp '"+tsV+"' copied!",Toast.LENGTH_SHORT).show();appendLog("Copied: "+tsV);}}return false;});btnProcess.setOnClickListener(v->startProcess());btnSaveFile.setOnClickListener(v->{if(currentSavableContent!=null){appendLog("Save clicked. Launching saver...");saveFileLauncher.launch(generateSuggestedFilename(currentSavableContent));}else{Toast.makeText(this,"Nothing to save.",Toast.LENGTH_SHORT).show();appendLog("Save clicked, nothing to save.");}});
    }

    private void handleSelectedApk(Uri u){selectedApkUri=u;tempApkPath=null;extractedPackageName=null;extractedTimestamp=null;currentSavableContent=null;String fn=getFileNameFromUri(u);if(tvSelectedPathLabel!=null){tvSelectedPathLabel.setText("APK:");tvSelectedPathValue.setText(fn);}else tvSelectedPathValue.setText("APK: "+fn);tvPackageName.setText("Package: (Parsing...)");tvTimestamp.setText("Timestamp: (Parsing...)");tvPackageName.setVisibility(View.VISIBLE);tvTimestamp.setVisibility(View.VISIBLE);appendLog("Selected APK: "+fn);appendLog("Copying & parsing APK...");setLoading(true);final boolean nTs=(currentDataMode==MainActivity.DataMode.TIMESTAMP_DAT||currentDataMode==MainActivity.DataMode.CHAINED_PROPERTIES);executorService.execute(()->{File tF=copyUriToTempFile(u);String ctp=null;String p=null;Long ts=null;String eM=null;if(tF!=null){ctp=tF.getAbsolutePath();appendLog("APK copied to: "+ctp);try{ParsedApkData pa=parseApk(ctp);p=pa.packageName;ts=pa.timestamp;eM=pa.errorMessage;if(p==null){appendLog("❌ APK Parse: Pkg name not found.");if(eM==null)eM="Pkg name not found.";}else appendLog(" -> Package: "+p);if(ts!=null)appendLog(" -> Timestamp: "+ts);else{if(nTs){appendLog("❌ APK Parse: TS not found (Required).");if(eM==null)eM="Required TS not found.";}else{appendLog(" -> Timestamp: (Not found/needed).");if(eM==null)eM="TS (optional) not found.";}}if(eM!=null&&!(eM.contains("optional")))appendLog("APK Parse Note: "+eM);}catch(Exception e){Log.e(TAG,"Err parsing APK",e);eM="Ex parsing APK: "+e.getMessage();appendLog("❌ "+eM);if(tF.exists()&&!tF.delete())Log.w(TAG,"Failed del partial temp: "+ctp);ctp=null;}}else{eM="Failed copy APK to temp.";appendLog("❌ "+eM);ctp=null;}final String fp=p;final Long ft=ts;final String fe=eM;final String fpt=ctp;mainThreadHandler.post(()->{extractedPackageName=fp;extractedTimestamp=ft;tempApkPath=fpt;tvPackageName.setText("Package: "+(fp!=null?fp:"(Not found)"));if(ft!=null){SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z",Locale.getDefault());tvTimestamp.setText("Timestamp: "+ft+"\n("+sdf.format(new Date(ft))+")");}else{String tst="Timestamp: ";if(fe!=null&&fe.contains("Required"))tst+=fe;else if(nTs)tst+="(Required, Not found)";else tst+="(Not found/needed)";tvTimestamp.setText(tst);}
    setLoading(false);updateUiState();});});}
    private static class ParsedApkData{String packageName;Long timestamp;String errorMessage;}
    private ParsedApkData parseApk(String apkPath){PackageManager pm=getPackageManager();PackageInfo pi;ParsedApkData r=new ParsedApkData();try{pi=pm.getPackageArchiveInfo(apkPath,PackageManager.GET_META_DATA);if(pi!=null){r.packageName=pi.packageName;ApplicationInfo ai=pi.applicationInfo;if(r.packageName!=null&&ai==null){try{ai=pm.getApplicationInfo(r.packageName,PackageManager.GET_META_DATA);}catch(PackageManager.NameNotFoundException e){Log.w(TAG,"AppInfo direct lookup fail "+r.packageName);if(pi.applicationInfo!=null)ai=pi.applicationInfo;}}if(r.packageName==null)r.errorMessage="Pkg name null in manifest.";if(ai!=null&&ai.metaData!=null){Bundle m=ai.metaData;String tsk=MainActivity.CryptoConstants.META_DATA_KEY_CLONE_TIMESTAMP;if(m.containsKey(tsk)){Object v=m.get(tsk);String ty=(v!=null)?v.getClass().getSimpleName():"null";Log.d(TAG,"Found '"+tsk+"'. Type: "+ty+", Val: "+v);if(v instanceof Long)r.timestamp=(Long)v;else if(v instanceof String){try{r.timestamp=Long.parseLong((String)v);}catch(NumberFormatException e){String er="TS Str '"+v+"' not Long.";r.errorMessage=(r.errorMessage==null)?er:r.errorMessage+". "+er;Log.w(TAG,er);}}else if(v instanceof Integer)r.timestamp=((Integer)v).longValue();else if(v!=null){String er="TS type ["+ty+"] unexp.";r.errorMessage=(r.errorMessage==null)?er:r.errorMessage+". "+er;Log.w(TAG,er);}else{String er="TS key '"+tsk+"' val null.";r.errorMessage=(r.errorMessage==null)?er:r.errorMessage+". "+er;Log.w(TAG,er);}}else{String er="Key '"+tsk+"' not in metaData.";if(r.errorMessage==null)r.errorMessage=er;Log.i(TAG,er);}}else{String er=(ai==null)?"AppInfo null.":"No metaData.";if(r.errorMessage==null)r.errorMessage=er;else r.errorMessage+=". "+er;Log.w(TAG,er);}}else r.errorMessage="Invalid APK/getPackageArchiveInfo fail.";}catch(Exception e){r.errorMessage="Ex parsing APK: "+e.getMessage();Log.e(TAG,"Gen parseApk ex",e);}if(r.timestamp==null&&r.errorMessage==null)r.errorMessage="TS undetermined.";return r;}
    private File copyUriToTempFile(Uri u){InputStream iS=null;OutputStream oS=null;File tF=null;try{String fN=getFileNameFromUri(u);String tFN="temp_apk_"+System.currentTimeMillis()+"_"+(fN.replaceAll("[^a-zA-Z0-9._-]","_"))+".apk";tF=new File(getCacheDir(),tFN);iS=getContentResolver().openInputStream(u);if(iS==null){Log.e(TAG,"Failed open InputStream: "+u);return null;}oS=new FileOutputStream(tF);byte[]b=new byte[8192];int by;long tot=0;while((by=iS.read(b))!=-1){oS.write(b,0,by);tot+=by;}oS.flush();Log.d(TAG,"Copied Uri to temp: "+tF.getAbsolutePath()+" ("+tot+" bytes)");return tF;}catch(Exception e){Log.e(TAG,"Err copy Uri to temp",e);if(tF!=null&&tF.exists())if(!tF.delete())Log.w(TAG,"Failed del partial temp: "+tF.getAbsolutePath());return null;}finally{try{if(iS!=null)iS.close();}catch(IOException ex){Log.e(TAG,"Err close input",ex);}try{if(oS!=null)oS.close();}catch(IOException ex){Log.e(TAG,"Err close output",ex);}}}
    private void deleteTempApkFile(){if(tempApkPath!=null){File tf=new File(tempApkPath);if(tf.exists())if(tf.delete())appendLog("Deleted temp APK: "+tempApkPath);else appendLog("⚠️ Failed del temp APK.");tempApkPath=null;}}

    private void startProcess(){
        if(currentDataMode==null){showError("Select Data Type.");setLoading(false);return;}
        final boolean iE=currentOperation==MainActivity.OperationMode.ENCRYPT;
        boolean rAS=true,rP=true,rIF=iE;
        boolean rODC = iE && (currentDataMode == MainActivity.DataMode.CHAINED_PROPERTIES || currentDataMode == MainActivity.DataMode.CLONE_SETTINGS);
        boolean cMRTs=requiresTimestamp();

        if(rAS&&selectedApkUri==null){showError("Select Cloned APK.");setLoading(false);return;}
        if(rIF&&selectedInputFileUri==null){showError("Select plain input file for encrypt.");setLoading(false);return;}
        if(rODC&&selectedEncryptOutputDirUri==null){showError("Select output dir for " + currentDataMode.name() + " Encrypt.");setLoading(false);return;}
        if(rP&&(extractedPackageName==null||extractedPackageName.isEmpty())){showError("Package name missing. Parse APK.");setLoading(false);return;}

        Long tsTU=extractedTimestamp;
        if(currentDataMode==MainActivity.DataMode.TIMESTAMP_DAT && tsTU==null){
            showError("Timestamp required for .dat. Parse APK.");setLoading(false);return;
        }

        if(cMRTs&&tsTU==null){showError("Timestamp missing/invalid. Required for "+currentDataMode.name()+".");setLoading(false);return;}
        if(rAS&&tempApkPath==null && currentOperation==MainActivity.OperationMode.DECRYPT){showError("Temp APK path not available. Parse APK.");setLoading(false);return;}

        setLoading(true);currentSavableContent=null;btnSaveFile.setEnabled(false);clearLog();
        appendLog("--- Starting "+currentOperation.name()+" ["+currentDataMode.name()+"] ---");
        if(extractedPackageName!=null)appendLog("Package: "+extractedPackageName);else if(rP)appendLog("WARN: Package MISSING!");
        if(tsTU!=null)appendLog("Effective Timestamp: "+tsTU+" (Parsed)");
        else if(cMRTs)appendLog("WARN: Effective Timestamp MISSING (Required)!");

        final String ap=tempApkPath;final Uri iu=selectedInputFileUri;final Uri ou=selectedEncryptOutputDirUri;
        final String pn=extractedPackageName;final Long ftsu=tsTU;
        final MainActivity.OperationMode om=currentOperation;final MainActivity.DataMode dm=currentDataMode;

        executorService.execute(()->{
            String pe=null;
            try{
                if(om==MainActivity.OperationMode.DECRYPT){
                    if(ap==null&&requiresApkDataSource())throw new IOException("APK path null for decrypt from APK.");
                    switch(dm){
                        case TIMESTAMP_DAT:decryptTimestampDatFromApk(ap,pn,ftsu);break;
                        case CHAINED_PROPERTIES:decryptChainedPropertiesFromApk(ap,pn,ftsu);break;
                        case CLONE_SETTINGS:decryptCloneSettingsFromApk(ap,pn);break;
                        case APP_DATA:decryptAppDataFromApk(ap,pn);break;
                        case LEGACY_STRINGS_PROPERTIES:decryptLegacyStringsPropertiesFromApk(ap,pn);break;
                        default:throw new IllegalArgumentException("Unsupp decrypt mode: "+dm);
                    }
                } else { // ENCRYPT
                    performEncryption(dm,iu,ou,pn,ftsu,ap);
                }
            }catch(Exception e){Log.e(TAG,"Err background processing",e);pe="❌ Unexpected Err: "+e.getClass().getSimpleName()+" - "+e.getMessage();appendLog(pe);}
            finally{
                if(pe!=null)mainThreadHandler.post(()->currentSavableContent=null);
                final String fpe=pe;
                mainThreadHandler.post(()->{setLoading(false);updateUiState();appendLog("--- Processing Finished "+(fpe==null?"OK":"with ERRORS")+" ---");});
            }
        });
    }
    private boolean requiresApkDataSource(){return currentOperation==OperationMode.DECRYPT;}

    private void decryptTimestampDatBytes(byte[] encB,String tsStr,String inFn){
        appendLog("\n === Starting app_cloner.dat Decrypt === ");
        appendLog("Input: "+inFn);
        appendLog("Provided TS: '"+tsStr+"'");
        if(encB==null||encB.length==0){
            appendLog("❌ ERROR: Encrypted bytes null/empty.");
            handleDecryptionResult(null,MainActivity.DataMode.TIMESTAMP_DAT,inFn);
            appendLog(" === Finished .dat Decrypt (Early Exit) === ");
            return;
        }
        appendLog("Encrypted size: "+encB.length+" bytes.");
        if(encB.length > 0)appendLog("Encrypted (hex, first 32): "+CryptoUtils.bytesToHex(Arrays.copyOfRange(encB,0,Math.min(encB.length,32))));

        if(encB.length % MainActivity.CryptoConstants.AES_BLOCK_SIZE != 0) {
            appendLog("⚠️ NOTE: Encrypted size ("+encB.length+") NOT multiple of AES block size ("+MainActivity.CryptoConstants.AES_BLOCK_SIZE+"). PKCS5Padding should handle.");
        } else {
            appendLog("INFO: Encrypted size IS multiple of AES block size.");
        }

        byte[] decryptedData = null;
        String keyAttempted = "none";

        // --- Attempt 1: New (Kotlin-aligned) Base Key ---
        appendLog("\n[*] Attempt 1: Decrypting with new (Kotlin-aligned) base key...");
        try{
            byte[] derivedKey1 = CryptoUtils.deriveKeyFromTimestamp(MainActivity.CryptoConstants.BASE_KEY_B64_FOR_TIMESTAMP_DAT, tsStr);
            if(derivedKey1 != null && derivedKey1.length > 0){
                appendLog("   Derived key (new, hex): "+CryptoUtils.bytesToHex(derivedKey1));
                decryptedData = CryptoUtils.decryptAesEcbPkcs5(encB, derivedKey1);
                if (decryptedData != null && CryptoUtils.isValidDexHeader(decryptedData)) {
                    keyAttempted = "new_key";
                    appendLog("✅ SUCCESS! Decrypted with new key. Output valid DEX.");
                } else {
                    appendLog("   New key decryption result: " + (decryptedData == null ? "null" : "not valid DEX header"));
                }
            } else {
                appendLog("   Failed to derive key with new base key.");
            }
        }catch(Exception e){
            appendLog("❌ EXCEPTION during new key decryption attempt: "+e.getClass().getSimpleName()+" - "+e.getMessage());
            Log.e(TAG,"New key decryption ex",e);
        }

        // --- Attempt 2: Old (Smali/Python) Base Key, IF Attempt 1 failed ---
        if (decryptedData == null || !CryptoUtils.isValidDexHeader(decryptedData)) {
            appendLog("\n[*] Attempt 2: Decrypting with old (Smali/Python) base key...");
            decryptedData = null; // Reset for second attempt
            try{
                byte[] derivedKey2 = CryptoUtils.deriveKeyFromTimestamp(MainActivity.CryptoConstants.ORIGINAL_SMALI_BASE_KEY_B64, tsStr);
                if(derivedKey2 != null && derivedKey2.length > 0){
                    appendLog("   Derived key (old, hex): "+CryptoUtils.bytesToHex(derivedKey2));
                    decryptedData = CryptoUtils.decryptAesEcbPkcs5(encB, derivedKey2);
                    if (decryptedData != null && CryptoUtils.isValidDexHeader(decryptedData)) {
                        keyAttempted = "old_key";
                        appendLog("✅ SUCCESS! Decrypted with old key. Output valid DEX.");
                    } else {
                        appendLog("   Old key decryption result: " + (decryptedData == null ? "null" : "not valid DEX header"));
                    }
                } else {
                    appendLog("   Failed to derive key with old base key.");
                }
            }catch(Exception e){
                appendLog("❌ EXCEPTION during old key decryption attempt: "+e.getClass().getSimpleName()+" - "+e.getMessage());
                Log.e(TAG,"Old key decryption ex",e);
            }
        }

        // --- Final Result Handling ---
        if(decryptedData != null && CryptoUtils.isValidDexHeader(decryptedData)){
            appendLog("\nFinal Result: app_cloner.dat decrypted successfully with " + keyAttempted + ".");
            appendLog("Decrypted size: "+decryptedData.length+" bytes.");
        } else {
            appendLog("\n################################################################\n### ❗❗❗ app_cloner.dat DECRYPTION FAILED ALL ATTEMPTS ❗❗❗ ###\n################################################################");
            appendLog("   REASON: Neither the new nor old base key yielded valid DEX data.");
            appendLog("   Input TS: '"+tsStr+"'");
            if(encB.length > 0) appendLog("   Encrypted (hex, first 32): "+CryptoUtils.bytesToHex(Arrays.copyOfRange(encB,0,Math.min(encB.length,32))));
            else appendLog("   Encrypted data was empty.");
            if (decryptedData != null && decryptedData.length > 0) {
                 appendLog("   Last attempted decryption output (hex, first 16): "+CryptoUtils.bytesToHex(Arrays.copyOfRange(decryptedData,0,Math.min(decryptedData.length,16))));
            } else {
                appendLog("   Last attempted decryption produced no data.");
            }
            appendLog("   POSSIBLE CAUSES: Incorrect timestamp, corrupted .dat file, or unknown new encryption method.");
            appendLog("################################################################");
            decryptedData = null; // Ensure null if failed
        }
        appendLog(" === Finished .dat Decrypt Attempt === \n");
        handleDecryptionResult(decryptedData,MainActivity.DataMode.TIMESTAMP_DAT,inFn);
    }
    private void decryptTimestampDatFromApk(String ap,String pn,Long ts){String e="assets/app_cloner.dat",i="app_cloner.dat";appendLog("Decrypting '"+e+"' from APK (TS DAT)...");if(ts==null){appendLog("❌ Err: TS NULL (Required).");handleDecryptionResult(null,MainActivity.DataMode.TIMESTAMP_DAT,i);return;}if(ap==null){appendLog("❌ Err: APK Path NULL.");handleDecryptionResult(null,MainActivity.DataMode.TIMESTAMP_DAT,i);return;}byte[]b=findAndReadApkEntry(ap,e);if(b==null){appendLog(" -> Entry '"+e+"' not found/unreadable.");handleDecryptionResult(null,MainActivity.DataMode.TIMESTAMP_DAT,i);return;}if(b.length==0)appendLog("❌ Warn: Found '"+e+"' but empty.");decryptTimestampDatBytes(b,String.valueOf(ts),i);}
    private void decryptAppDataFromApk(String ap,String pn){String e="assets/"+pn+".app_data",i=pn+".app_data";appendLog("Decrypting '"+e+"' from APK (App Data)...");if(pn==null||pn.isEmpty()){appendLog("❌ Err: Pkg name missing.");handleDecryptionResult(null,MainActivity.DataMode.APP_DATA,i);return;}if(ap==null){appendLog("❌ Err: APK Path NULL.");handleDecryptionResult(null,MainActivity.DataMode.APP_DATA,i);return;}byte[]b=findAndReadApkEntry(ap,e);if(b==null){appendLog(" -> Entry '"+e+"' not found/unreadable.");handleDecryptionResult(null,MainActivity.DataMode.APP_DATA,i);return;}if(b.length==0)appendLog("❌ Warn: Found '"+e+"' but empty.");decryptAppDataBytes(b,pn,i);}
    
    /**
     * Decrypts legacy strings.properties file from old AppCloner versions.
     * Uses LegacyDecryptor with hardcoded AES key for backward compatibility.
     */
    private void decryptLegacyStringsPropertiesFromApk(String ap, String pn) {
        String entryName = "assets/strings.properties";
        String inputFilename = "strings.properties";
        appendLog("Decrypting '" + entryName + "' from APK (Legacy Single Properties)...");
        appendLog("Using legacy decryption method for old AppCloner versions.");
        
        if (ap == null) {
            appendLog("❌ Err: APK Path NULL.");
            handleDecryptionResult(null, MainActivity.DataMode.LEGACY_STRINGS_PROPERTIES, inputFilename);
            return;
        }
        
        byte[] encryptedBytes = findAndReadApkEntry(ap, entryName);
        if (encryptedBytes == null) {
            appendLog(" -> Entry '" + entryName + "' not found/unreadable.");
            handleDecryptionResult(null, MainActivity.DataMode.LEGACY_STRINGS_PROPERTIES, inputFilename);
            return;
        }
        
        if (encryptedBytes.length == 0) {
            appendLog("❌ Warn: Found '" + entryName + "' but empty.");
            handleDecryptionResult(null, MainActivity.DataMode.LEGACY_STRINGS_PROPERTIES, inputFilename);
            return;
        }
        
        appendLog("[*] Found strings.properties (" + encryptedBytes.length + " bytes).");
        appendLog("[*] Decrypting with legacy hardcoded key (AES-ECB/PKCS5)...");
        
        // Use the new LegacyDecryptor class
        byte[] decryptedBytes = LegacyDecryptor.decryptLegacyStringsProperties(encryptedBytes);
        
        if (decryptedBytes != null && decryptedBytes.length > 0) {
            // Verify it looks like a properties file
            if (LegacyDecryptor.isValidPropertiesFormat(decryptedBytes)) {
                appendLog("✅ Legacy strings.properties decryption successful (" + decryptedBytes.length + " bytes).");
                handleDecryptionResult(decryptedBytes, MainActivity.DataMode.LEGACY_STRINGS_PROPERTIES, inputFilename);
            } else {
                appendLog("⚠️ Decryption completed but output doesn't look like properties format.");
                appendLog("   Saving anyway - please verify output manually.");
                handleDecryptionResult(decryptedBytes, MainActivity.DataMode.LEGACY_STRINGS_PROPERTIES, inputFilename);
            }
        } else {
            appendLog("❌ Legacy strings.properties decryption FAILED.");
            appendLog("   Possible causes: Wrong key, corrupted file, or not encrypted with legacy method.");
            handleDecryptionResult(null, MainActivity.DataMode.LEGACY_STRINGS_PROPERTIES, inputFilename);
        }
    }
    
    private void decryptCloneSettingsFromApk(String ap,String pn){appendLog("Starting Clone Settings Decrypt. Pkg: "+pn);if(pn==null||pn.isEmpty()){appendLog("❌ Err: Pkg name missing.");handleDecryptionResultString(null,MainActivity.DataMode.CLONE_SETTINGS,pn,"err_no_pkg.json");return;}if(ap==null){appendLog("❌ Err: APK Path NULL.");handleDecryptionResultString(null,MainActivity.DataMode.CLONE_SETTINGS,pn,"err_no_apk.json");return;}StringBuilder sb=new StringBuilder();int x=0,fc=0;String em=null;Map<String,ZipEntry>ch=new HashMap<>();try(ZipFile zf=new ZipFile(ap)){appendLog("Searching MD5 resources (idx 0,1...):");while(true){String fm=CryptoUtils.generateSettingsFilename(pn,x);appendLog("  -> Look part "+x+": "+fm);ZipEntry en=findApkEntryByName(zf,ch,fm,true);if(en!=null){String fN=en.getName();appendLog("      [+] Found: "+fN+" (Size: "+en.getSize()+")");byte[]cb=readZipEntryContent(zf,en);if(cb!=null){String c=new String(cb,StandardCharsets.UTF_8).trim();if(!c.isEmpty()){sb.append(c);fc++;}else appendLog("      [!] Part "+x+" empty.");}else{appendLog("      [!] Err reading "+fN+". Stopping.");em="Err reading: "+fN;break;}}else{if(x==0){appendLog("      [-] Part 0 ("+fm+") not found. Cannot proceed.");em="Initial part (idx 0, "+fm+") not found.";}else appendLog("      [-] Part "+x+" ("+fm+") not found. End sequence.");break;}x++;if(x>100){appendLog("      [!] Max part (100) reached.");em="Max parts limit.";break;}}if(fc==0){String fe=(em!=null)?em:"No valid settings parts.";appendLog("❌ "+fe);handleDecryptionResultString(null,MainActivity.DataMode.CLONE_SETTINGS,pn,"err_no_parts.json");return;}appendLog("[*] Assembled "+fc+" part(s). Base64 len: "+sb.length());appendLog("[*] Deriving key for: "+pn);byte[]dk=CryptoUtils.deriveDynamicSettingsKey(pn);appendLog("[*] Derived key (Hex): "+CryptoUtils.bytesToHex(dk));appendLog("[*] Decoding B64 & AES decrypt (PKCS7)...");String dj=CryptoUtils.decryptAesEcbPkcs7Base64(sb.toString(),dk);handleDecryptionResultString(dj,MainActivity.DataMode.CLONE_SETTINGS,pn,"cloneSettings_dec.json");if(dj!=null){String tj=dj.trim();if((tj.startsWith("{")&&tj.endsWith("}"))||(tj.startsWith("[")&&tj.endsWith("]")))appendLog("   Result JSON like.");else appendLog("   ⚠️ Warn: Result NOT JSON like.");}}catch(Exception e){em=(em!=null?em+" | ":"")+"Ex settings decrypt: "+e.getMessage();Log.e(TAG,em,e);appendLog("❌ "+em);handleDecryptionResultString(null,MainActivity.DataMode.CLONE_SETTINGS,pn,"err_unknown.json");}}
    private void decryptChainedPropertiesFromApk(String ap,String pn,Long ts){appendLog("Starting Chained Props Decrypt. Pkg: "+pn+", TS: "+ts);if(pn==null||pn.isEmpty()||ts==null){appendLog("❌ Err: Pkg/TS missing.");handleDecryptionResultString(null,MainActivity.DataMode.CHAINED_PROPERTIES,pn,"err_input.props");return;}if(ap==null){appendLog("❌ Err: APK Path NULL.");handleDecryptionResultString(null,MainActivity.DataMode.CHAINED_PROPERTIES,pn,"err_no_apk.props");return;}Map<String,String>p=new LinkedHashMap<>();int fc=0;String m=null;Map<String,ZipEntry>ch=new HashMap<>();try(ZipFile zf=new ZipFile(ap)){String ik=MainActivity.CryptoConstants.CHAINED_KEY_PREFIX+pn+ts;String ck=CryptoUtils.generateMd5Hex(ik);appendLog("Initial Key MD5: "+ck);for(int x=0;x<MainActivity.CryptoConstants.CHAINED_MAX_DEPTH;x++){appendLog("\n--- Chain Step "+(x+1)+" ---");String rn=CryptoUtils.generateChainedPropertiesFilename(ck);appendLog("  -> Look file: "+rn+" (key MD5: "+ck+")");ZipEntry en=findApkEntryByName(zf,ch,rn,true);if(en!=null){String fN=en.getName();appendLog("      [+] Found: "+fN+" (Size: "+en.getSize()+")");fc++;byte[]eB=readZipEntryContent(zf,en);if(eB==null||eB.length==0){m="      [!] Entry '"+fN+"' empty/unreadable. Stop.";appendLog(m);break;}byte[]sk=CryptoUtils.getChainedSimpleCryptKeyBytes(ck);appendLog("      [*] Decrypt "+fN+" key MD5: "+ck);Log.d(TAG,"Chained Decrypt Key(HEX '"+ck+"'): "+CryptoUtils.bytesToHex(sk));byte[]dB=CryptoUtils.decryptAesEcbPkcs7(eB,sk);if(dB!=null){appendLog("      [*] Decrypted "+dB.length+" bytes. Parsing...");Map<String,String>cp=PropertiesParser.parseProperties(dB);if(!cp.isEmpty()){appendLog("      [*] Parsed "+cp.size()+" props.");p.putAll(cp);}else appendLog("      [*] Parsed 0 props.");}else{m="      [!] Decrypt fail (Key MD5: "+ck+"). Stop.";appendLog(m);break;}ck=rn;appendLog("      [*] Next key MD5 source: "+ck);}else{if(x==0)m="      [-] Initial file ("+rn+") not found.";else m="      [-] File "+rn+" not found. End chain.";appendLog(m);break;}}if(p.isEmpty()){if(m==null)m="No props decrypted.";if(fc==0&&!m.contains("Initial file"))m+=" (No files found).";appendLog("❌ "+m);handleDecryptionResultString(null,MainActivity.DataMode.CHAINED_PROPERTIES,pn,"err_no_props.props");return;}else if(m!=null&&!m.contains("End chain"))appendLog("⚠️ Chain stopped: "+m);appendLog("\n[*] Formatting "+p.size()+" props from "+fc+" file(s)...");String fp=PropertiesParser.formatProperties(p);handleDecryptionResultString(fp,MainActivity.DataMode.CHAINED_PROPERTIES,pn,"strings_dec.properties");}catch(Exception e){m=(m!=null?em+" | ":"")+"Ex chained decrypt: "+e.getMessage();Log.e(TAG,m,e);appendLog("❌ "+m);handleDecryptionResultString(null,MainActivity.DataMode.CHAINED_PROPERTIES,pn,"err_unknown.props");}}
    private void decryptAppDataBytes(byte[]eB,String pN,String iN){appendLog("Decrypt App Data bytes (Size: "+(eB!=null?eB.length:"null")+")");if(eB==null||eB.length==0){appendLog("Input AppData empty/null.");handleDecryptionResult(null,MainActivity.DataMode.APP_DATA,iN);return;}byte[]dB=null;String mt="None";appendLog("[*] Try standard App Data decrypt (XOR)...");try{byte[]xK=CryptoUtils.getAppDataXorKey(pN);appendLog("   XOR Key (pkg '"+pN+"') (Hex: "+CryptoUtils.bytesToHex(xK)+")");byte[]xR=CryptoUtils.performXor(eB,xK);if(isValidZipData(xR)){appendLog("✅ Standard XOR OK. Output valid ZIP.");dB=xR;mt="XOR (Standard)";}else appendLog("[-] Standard XOR -> invalid ZIP.");}catch(Exception e){appendLog("❌ Err XOR decrypt App Data: "+e.getMessage());Log.e(TAG,"AppData XOR Err",e);}if(dB==null){appendLog("\n[*] XOR fail/non-ZIP. Try legacy App Data decrypt (AES PKCS7)...");try{byte[]aK=CryptoUtils.getAppDataAesLegacyKey(pN);appendLog("   Legacy AES Key (Hex): "+CryptoUtils.bytesToHex(aK));if(eB.length%MainActivity.CryptoConstants.AES_BLOCK_SIZE!=0)appendLog("   ⚠️ Warn: Encrypt size legacy AES NOT multiple block. PKCS7 expect.");byte[]aR=CryptoUtils.decryptAesEcbPkcs7(eB,aK);if(aR!=null){if(isValidZipData(aR)){appendLog("✅ Legacy AES OK. Output valid ZIP.");dB=aR;mt="AES (Legacy)";}else appendLog("[-] Legacy AES -> invalid ZIP (decrypt OK).");}else appendLog("❌ Legacy AES decrypt failed (null). Key wrong/data corrupt.");}catch(Exception e){appendLog("❌ Err legacy AES decrypt App Data: "+e.getMessage());Log.e(TAG,"AppData AES Err",e);}}if(dB!=null){handleDecryptionResult(dB,MainActivity.DataMode.APP_DATA,iN);appendLog("\n--- App Data Decrypt Finished (Method: "+mt+") ---");}else{appendLog("\n❌ App Data Decrypt Failed (XOR & legacy AES).");mainThreadHandler.post(()->currentSavableContent=null);updateUiState();}}
    private void handleDecryptionResult(byte[]b,MainActivity.DataMode m,String f){final String p=extractedPackageName;if(b!=null){appendLog("✅ Decrypt OK ("+b.length+" bytes). Save ready.");final byte[]r=b;mainThreadHandler.post(()->currentSavableContent=new SavableContent(r,m,MainActivity.OperationMode.DECRYPT,p,f));}else{appendLog("❌ Decrypt FAILED. No data.");mainThreadHandler.post(()->currentSavableContent=null);}mainThreadHandler.post(this::updateUiState);}
    private void handleDecryptionResultString(String s,MainActivity.DataMode m,String pC,String f){final String fp=(pC!=null)?pC:extractedPackageName;if(s!=null){appendLog("✅ Decrypt OK (String len "+s.length()+"). Save ready.");final String r=s;mainThreadHandler.post(()->currentSavableContent=new SavableContent(r,m,MainActivity.OperationMode.DECRYPT,fp,f));}else{appendLog("❌ Decrypt FAILED. No data.");mainThreadHandler.post(()->currentSavableContent=null);}mainThreadHandler.post(this::updateUiState);}
    private void performEncryption(MainActivity.DataMode d,Uri iu,Uri du,String pn,Long t,String ap){appendLog("Starting Encrypt for "+d.name());if(iu==null){appendLog("❌ Encrypt Err: Input URI null.");handleEncryptionResult(null,d,"err_no_in_uri");return;}if((d==MainActivity.DataMode.TIMESTAMP_DAT||d==MainActivity.DataMode.CHAINED_PROPERTIES)&&t==null){appendLog("❌ Encrypt Err: TS null (Req for "+d.name()+").");handleEncryptionResult(null,d,getFileNameFromUri(iu));return;}if((d==MainActivity.DataMode.CLONE_SETTINGS||d==MainActivity.DataMode.APP_DATA||d==MainActivity.DataMode.CHAINED_PROPERTIES)&&(pn==null||pn.isEmpty())){appendLog("❌ Encrypt Err: Pkg name null/empty (Req for "+d.name()+").");handleEncryptionResult(null,d,getFileNameFromUri(iu));return;}if((d==MainActivity.DataMode.CHAINED_PROPERTIES||d==MainActivity.DataMode.CLONE_SETTINGS)&&du==null){appendLog("❌ Encrypt Err: Out dir URI null (Req for "+d.name()+").");handleEncryptionResult(null,d,getFileNameFromUri(iu));return;}if(d==MainActivity.DataMode.CLONE_SETTINGS&&ap==null){appendLog("❌ Encrypt Err: Source APK path needed for Clone Settings chunking rule.");handleEncryptionResult(null,d,getFileNameFromUri(iu));return;}
    switch(d){
        case TIMESTAMP_DAT:encryptTimestampDatFile(iu,String.valueOf(t));break;
        case CHAINED_PROPERTIES:encryptChainedProperties(iu,du,pn,t);break;
        case CLONE_SETTINGS:encryptCloneSettings(iu,du,pn,ap);break;
        case APP_DATA:encryptAppData(iu,pn);break;
        case LEGACY_STRINGS_PROPERTIES:
            appendLog("⚠️ Legacy properties encryption not recommended.");
            appendLog("   This mode is for decryption only (old AppCloner versions).");
            handleEncryptionResult(null,d,"legacy_not_supported.txt");
            break;
        default:appendLog("❌ Invalid encrypt mode: "+d);mainThreadHandler.post(()->currentSavableContent=null);updateUiState();break;
    }}

    private void encryptTimestampDatFile(Uri u,String s){String f=getFileNameFromUri(u);appendLog("Encrypt TS DAT: "+f+" (TS: "+s+")");byte[]b=readBytesFromUri(u);if(b==null||b.length==0){appendLog("❌ Input '"+f+"' empty/unreadable.");handleEncryptionResult(null,MainActivity.DataMode.TIMESTAMP_DAT,f);return;}appendLog("Read "+b.length+" bytes from "+f+".");byte[]k;try{k=CryptoUtils.deriveKeyFromTimestamp(s);}catch(Exception e){appendLog("❌ Err deriving key: "+e.getMessage());handleEncryptionResult(null,MainActivity.DataMode.TIMESTAMP_DAT,f);return;}byte[]eB=CryptoUtils.encryptAesEcbPkcs5(b,k);handleEncryptionResult(eB,MainActivity.DataMode.TIMESTAMP_DAT,f);}
    private void encryptCloneSettings(Uri u, Uri outputDirUri, String p, String apkPath) {
        String f = getFileNameFromUri(u);
        appendLog("Encrypt Settings: " + f + " (Pkg: " + p + ")");
        appendLog("Applying dynamic chunking rule based on source APK...");

        DocumentFile outputDirDocFile = DocumentFile.fromTreeUri(this, outputDirUri);
        if (outputDirDocFile == null || !outputDirDocFile.isDirectory() || !outputDirDocFile.canWrite()) {
            appendLog("❌ Invalid or non-writable output directory.");
            handleEncryptionResult(null, MainActivity.DataMode.CLONE_SETTINGS, f);
            return;
        }

        if (apkPath == null) {
            appendLog("❌ APK path is null. Cannot determine chunk count.");
            handleEncryptionResult(null, MainActivity.DataMode.CLONE_SETTINGS, f);
            return;
        }

        // Step 1: Calculate the number of chunks
        int fileCount = countFilesInApkDirectory(apkPath, "com/applisto/appcloner/classes/");
        int numChunks = Math.max(1, fileCount - 25); // Enforce a minimum of 1 chunk

        appendLog("  -> Files in '.../classes/': " + fileCount);
        appendLog("  -> Calculated chunk count: max(1, " + fileCount + " - 25) = " + numChunks);

        // Step 2: Read and encrypt the input JSON file
        String jsonContent = readTextFromUri(u, StandardCharsets.UTF_8);
        if (jsonContent == null || jsonContent.trim().isEmpty()) {
            appendLog("❌ Input '" + f + "' empty/unreadable/no text.");
            handleEncryptionResult(null, MainActivity.DataMode.CLONE_SETTINGS, f);
            return;
        }
        appendLog("Read " + jsonContent.length() + " chars from " + f + ".");

        byte[] dynamicKey;
        try {
            dynamicKey = CryptoUtils.deriveDynamicSettingsKey(p);
            appendLog("Derived key (Hex): " + CryptoUtils.bytesToHex(dynamicKey));
        } catch (Exception e) {
            appendLog("❌ Err deriving key: " + e.getMessage());
            handleEncryptionResult(null, MainActivity.DataMode.CLONE_SETTINGS, f);
            return;
        }

        String encryptedBase64 = CryptoUtils.encryptAesEcbPkcs7ToBase64(jsonContent, dynamicKey);
        if (encryptedBase64 == null) {
            appendLog("❌ AES/Base64 encryption failed.");
            handleEncryptionResult(null, MainActivity.DataMode.CLONE_SETTINGS, f);
            return;
        }
        appendLog("Encrypted to Base64 (length: " + encryptedBase64.length() + ").");

        // Step 3: Split into chunks and save each to a file in the output directory
        int totalLength = encryptedBase64.length();
        int chunkSize = (totalLength + numChunks - 1) / numChunks; // Ceiling division
        int filesSavedCount = 0;
        boolean encryptionOk = false;

        try {
            for (int i = 0; i < numChunks; i++) {
                String chunkFilename = CryptoUtils.generateSettingsFilename(p, i);
                int start = i * chunkSize;
                int end = Math.min(start + chunkSize, totalLength);
                String chunkContent = encryptedBase64.substring(start, end);
                byte[] chunkBytes = chunkContent.getBytes(StandardCharsets.UTF_8);

                appendLog("\n--- Encrypt Chunk "+(i+1)+"/"+numChunks+" ---");
                appendLog("  Output filename hash: " + chunkFilename);
                saveBytesToFileSaf(outputDirDocFile, chunkFilename, "application/octet-stream", chunkBytes);
                appendLog("✅ Saved chunk " + (i + 1) + " to: " + chunkFilename + " (" + chunkBytes.length + " bytes)");
                filesSavedCount++;
            }
            encryptionOk = (filesSavedCount == numChunks);
        } catch (Exception e) {
            appendLog("\n❌ Err during Clone Settings chunking/saving: " + e.getMessage());
            Log.e(TAG, "Clone Settings Encrypt Err", e);
            encryptionOk = false;
        } finally {
            appendLog("\n--- Clone Settings Encrypt Summary ---");
            appendLog("Chunks Saved: " + filesSavedCount + "/" + numChunks);
            if(encryptionOk) appendLog("✅ Clone Settings encrypt OK.");
            else appendLog("❌ Clone Settings encrypt FAILED.");
            // Signal completion. No single file is generated, so data is null.
            handleEncryptionResult(null, MainActivity.DataMode.CLONE_SETTINGS, f);
        }
    }
    private void encryptChainedProperties(Uri u,Uri o,String p,long t){
        String iF=getFileNameFromUri(u);
        appendLog("Start Chained Props Encrypt. Pkg: "+p+", TS: "+t);
        appendLog("Input: "+iF);
        appendLog("OutDir: "+getDirNameFromTreeUri(o));
        byte[]pb=readBytesFromUri(u);
        if(pb==null||pb.length==0){
            appendLog("❌ Input '"+iF+"' empty/unreadable.");
            handleEncryptionResult(null,MainActivity.DataMode.CHAINED_PROPERTIES,iF);
            return;
        }
        Map<String,String>pm=PropertiesParser.parseProperties(pb);
        int totalProperties = pm.size();

        if(totalProperties==0){
            appendLog("No properties parsed from '"+iF+"'. No files to encrypt.");
            handleEncryptionResult(null,MainActivity.DataMode.CHAINED_PROPERTIES,iF);
            return;
        }

        List<Map.Entry<String,String>>pe=new ArrayList<>(pm.entrySet());

        // Use new constant for chained encryption chunks
        int numChunksToCreate = MainActivity.CryptoConstants.CHAINED_ENCRYPTION_CHUNK_COUNT;
        int basePropertiesPerChunk = totalProperties / numChunksToCreate;
        int remainderProperties = totalProperties % numChunksToCreate;

        List<Map<String, String>> chunks = new ArrayList<>();
        int currentPropIndex = 0;

        for (int i = 0; i < numChunksToCreate; i++) {
            Map<String, String> currentChunkMap = new LinkedHashMap<>();
            int chunkSize = basePropertiesPerChunk;
            if (i < remainderProperties) {
                chunkSize++;
            }
            int endPropIndex = currentPropIndex + chunkSize;
            for (int j = currentPropIndex; j < endPropIndex; j++) {
                currentChunkMap.put(pe.get(j).getKey(), pe.get(j).getValue());
            }
            chunks.add(currentChunkMap);
            currentPropIndex = endPropIndex;
        }

        final int actualNumChunksInList = chunks.size();
        appendLog("Splitting " + totalProperties + " props into " + actualNumChunksInList + " chunks.");

        DocumentFile oddf=DocumentFile.fromTreeUri(this,o);
        if(oddf==null||!oddf.isDirectory()||!oddf.canWrite()){
            appendLog("❌ Invalid/non-writable out dir.");
            handleEncryptionResult(null,MainActivity.DataMode.CHAINED_PROPERTIES,iF);
            return;
        }
        appendLog("Out dir valid: "+oddf.getName());
        int filesSavedCount = 0;
        boolean encryptionOk = false;
        try{
            String iks=MainActivity.CryptoConstants.CHAINED_KEY_PREFIX+p+t;
            String ckm=CryptoUtils.generateMd5Hex(iks);
            appendLog("Initial Key MD5: "+ckm);
            for(int i=0;i<actualNumChunksInList;i++){
                Map<String,String>cme=chunks.get(i);
                
                if (cme.isEmpty()) {
                    appendLog("--- Chunk " + (i+1) + "/" + actualNumChunksInList + " (Empty properties) ---");
                } else {
                    appendLog("\n--- Encrypt Chunk "+(i+1)+"/"+actualNumChunksInList+" ---");
                }

                String fc=PropertiesParser.formatProperties(cme);
                byte[]fb=fc.getBytes(StandardCharsets.UTF_8);
                
                byte[]sk=CryptoUtils.getChainedSimpleCryptKeyBytes(ckm);
                Log.d(TAG,"Chained Encrypt Key (HEX '"+ckm+"'): "+CryptoUtils.bytesToHex(sk));
                byte[]ecb=CryptoUtils.encryptAesEcbPkcs7(fb,sk);
                if(ecb==null)throw new IOException("AES encrypt fail chunk "+(i+1));
                String rfh=CryptoUtils.generateChainedPropertiesFilename(ckm);
                appendLog("  Output filename hash: "+rfh);
                saveBytesToFileSaf(oddf,rfh,"application/octet-stream",ecb);
                appendLog("✅ Saved chunk "+(i+1)+" to: "+rfh+" ("+ecb.length+" bytes)");
                filesSavedCount++;
                ckm=rfh;
                appendLog("      [*] Next key MD5 source: "+ckm);
            }
            encryptionOk=(filesSavedCount == numChunksToCreate);
        }catch(Exception e){
            appendLog("\n❌ Err Chained Props encrypt: "+e.getMessage());
            Log.e(TAG,"Chained Encrypt Err",e);
            encryptionOk=false;
        }finally{
            appendLog("\n--- Chained Props Encrypt Summary ---");
            appendLog("Chunks Processed: "+filesSavedCount+"/"+numChunksToCreate);
            if(encryptionOk)appendLog("✅ Chained Props encrypt OK.");
            else appendLog("❌ Chained Props encrypt FAILED.");
            handleEncryptionResult(null,MainActivity.DataMode.CHAINED_PROPERTIES,iF);
        }
    }
    private void encryptAppData(Uri u,String p){String f=getFileNameFromUri(u);appendLog("Encrypt App Data: "+f+" (Pkg: "+p+")");byte[]b=readBytesFromUri(u);if(b==null||b.length==0){appendLog("❌ Input '"+f+"' empty/unreadable.");handleEncryptionResult(null,MainActivity.DataMode.APP_DATA,f);return;}appendLog("Read "+b.length+" bytes from "+f+".");if(!isValidZipData(b))appendLog("⚠️ Warn: Input App Data NOT valid ZIP.");byte[]k;try{k=CryptoUtils.getAppDataXorKey(p);appendLog("XOR key (pkg '"+p+"') (Hex: "+CryptoUtils.bytesToHex(k)+")");}catch(Exception e){appendLog("❌ Err getting XOR key: "+e.getMessage());handleEncryptionResult(null,MainActivity.DataMode.APP_DATA,f);return;}byte[]eB;try{eB=CryptoUtils.performXor(b,k);}catch(Exception e){appendLog("❌ Err XOR App Data encrypt: "+e.getMessage());handleEncryptionResult(null,MainActivity.DataMode.APP_DATA,f);return;}handleEncryptionResult(eB,MainActivity.DataMode.APP_DATA,f);}



    private void handleEncryptionResult(Object d,MainActivity.DataMode m,String f){final String p=extractedPackageName;if(d!=null){int s=(d instanceof byte[])?((byte[])d).length:((String)d).length();appendLog("✅ Encrypt OK ("+s+((d instanceof String)?" chars":" bytes")+"). Save ready.");mainThreadHandler.post(()->currentSavableContent=new SavableContent(d,m,MainActivity.OperationMode.ENCRYPT,p,f));}else{if(m==MainActivity.DataMode.CHAINED_PROPERTIES||m==MainActivity.DataMode.CLONE_SETTINGS);else appendLog("❌ Encrypt FAILED (Null). No data.");mainThreadHandler.post(()->{if(!((m==MainActivity.DataMode.CHAINED_PROPERTIES||m==MainActivity.DataMode.CLONE_SETTINGS)&&d==null))currentSavableContent=null;});}mainThreadHandler.post(this::updateUiState);}

    private int countFilesInApkDirectory(String apkPath, String dirPath) {
        int count = 0;
        if (apkPath == null || dirPath == null) {
            appendLog("❌ Cannot count files: APK path or directory path is null.");
            return 0;
        }
        try (ZipFile zipFile = new ZipFile(apkPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory() && entry.getName().startsWith(dirPath)) {
                    count++;
                }
            }
        } catch (IOException e) {
            appendLog("❌ Error counting files in APK: " + e.getMessage());
            Log.e(TAG, "countFilesInApkDirectory failed for " + apkPath, e);
            return 0; // Return 0 on error
        }
        return count;
    }
    private byte[] findAndReadApkEntry(String p,String e){if(p==null||e==null){appendLog("❌ Err findRead: Path null.");return null;}Log.d(TAG,"Read entry '"+e+"' APK: "+p);try(ZipFile z=new ZipFile(p)){ZipEntry n=z.getEntry(e);if(n==null){appendLog(" -> Entry '"+e+"' not in APK.");return null;}appendLog(" -> Found '"+e+"' (Size: "+n.getSize()+"). Reading...");return readZipEntryContent(z,n);}catch(Exception ex){appendLog("❌ Ex reading APK entry '"+e+"': "+ex.getMessage());Log.e(TAG,"Ex read APK entry",ex);return null;}}
    private ZipEntry findApkEntryByName(ZipFile z,Map<String,ZipEntry>c,String bf,boolean ic){String tl=ic?bf.toLowerCase(Locale.ROOT):null;String[]ps={"res/raw/","assets/","com/applisto/appcloner/classes/",""};Log.d(TAG," Search base: "+bf+(ic?" (case-ins)":""));Enumeration<? extends ZipEntry>es=z.entries();while(es.hasMoreElements()){ZipEntry e=es.nextElement();if(e.isDirectory())continue;String ef=e.getName(),eb=ef;for(String pfx:ps)if(!pfx.isEmpty()&&ef.startsWith(pfx)){eb=ef.substring(pfx.length());break;}if(ic){if(eb.toLowerCase(Locale.ROOT).equals(tl)){Log.d(TAG," [+] Found(ins): "+ef+" (base: "+eb+")");return e;}}else if(eb.equals(bf)){Log.d(TAG," [+] Found(sens): "+ef+" (base: "+eb+")");return e;}}Log.d(TAG," [-] Not found base: "+bf);return null;}
    private byte[] readZipEntryContent(ZipFile z,ZipEntry e)throws IOException{if(e.getSize()==0){appendLog("INFO: Zip entry '"+e.getName()+"' size 0.");return new byte[0];}long s=e.getSize();if(s<0||s>150*1024*1024){Log.w(TAG,"Zip entry '"+e.getName()+"' unusual size ("+s+"). Default buffer.");s=8192;}int cap=(int)Math.min(s,Integer.MAX_VALUE-8);try(InputStream i=z.getInputStream(e);ByteArrayOutputStream bs=new ByteArrayOutputStream(cap)){byte[]b=new byte[8192];int r;while((r=i.read(b))!=-1)bs.write(b,0,r);appendLog("Read "+bs.size()+" bytes from: "+e.getName());return bs.toByteArray();}catch(IOException ex){appendLog("❌ IOEx reading zip entry '"+e.getName()+"': "+ex.getMessage());throw ex;}}
    private byte[] readBytesFromUri(Uri u){if(u==null){appendLog("❌ Err readBytes: URI null.");return null;}String f=getFileNameFromUri(u);ContentResolver rs=getContentResolver();ByteArrayOutputStream b=new ByteArrayOutputStream();InputStream i=null;BufferedInputStream bi=null;try{i=rs.openInputStream(u);if(i==null)throw new IOException("Failed open InputStream: "+u);bi=new BufferedInputStream(i);byte[]bf=new byte[8192];int r;while((r=bi.read(bf))!=-1)b.write(bf,0,r);appendLog("Read "+b.size()+" bytes URI: "+f);return b.toByteArray();}catch(Exception e){appendLog("❌ Err reading bytes URI '"+f+"': "+e.getMessage());Log.e(TAG,"Err readBytes URI",e);return null;}finally{try{if(bi!=null)bi.close();}catch(IOException ig){}try{if(i!=null)i.close();}catch(IOException ig){}try{b.close();}catch(IOException ig){}}}
    private String readTextFromUri(Uri u,Charset cs){if(u==null){appendLog("❌ Err readText: URI null.");return null;}String f=getFileNameFromUri(u);ContentResolver rs=getContentResolver();StringBuilder s=new StringBuilder();InputStream i=null;BufferedReader r=null;try{i=rs.openInputStream(u);if(i==null)throw new IOException("Failed open InputStream: "+u);r=new BufferedReader(new InputStreamReader(i,cs));String l;while((l=r.readLine())!=null)s.append(l).append('\n');if(s.length()>0)s.setLength(s.length()-1);appendLog("Read "+s.length()+" chars URI: "+f);return s.toString();}catch(Exception e){appendLog("❌ Err reading text URI '"+f+"': "+e.getMessage());Log.e(TAG,"Err readText URI",e);return null;}finally{try{if(r!=null)r.close();}catch(IOException ig){}try{if(i!=null)i.close();}catch(IOException ig){}}}
    private void saveBytesToFileSaf(DocumentFile p,String f,String m,byte[]d)throws IOException{if(!p.canWrite())throw new IOException("Cannot write out dir: "+p.getName());DocumentFile ef=p.findFile(f);if(ef!=null){Log.d(TAG,"File '"+f+"' exists. Deleting.");if(!ef.delete())Log.w(TAG,"Failed del exist '"+f+"'.");}DocumentFile tf=p.createFile(m,f);if(tf==null)throw new IOException("Failed create file '"+f+"'.");OutputStream o=null;try{o=getContentResolver().openOutputStream(tf.getUri(),"w");if(o==null)throw new IOException("Failed open OutputStream: "+f);try(BufferedOutputStream bo=new BufferedOutputStream(o)){bo.write(d);bo.flush();}appendLog("Saved "+d.length+" bytes to: "+f);}catch(Exception e){if(tf.exists())try{tf.delete();}catch(Exception de){Log.w(TAG,"Failed del partial '"+f+"'.",de);}throw new IOException("Err writing '"+f+"': "+e.getMessage(),e);}finally{if(o!=null)try{o.close();}catch(IOException ig){}}}
    private void saveContentToFile(SavableContent c,Uri tu){setLoading(true);String tf=getFileNameFromUri(tu);appendLog("💾 Saving result to: "+tf);final Object ds=c.data;executorService.execute(()->{boolean ok=false;String em=null;OutputStream o=null;try{o=getContentResolver().openOutputStream(tu,"w");if(o==null)throw new IOException("Failed open OutputStream: "+tu);writeContentToStream(ds,o);ok=true;}catch(Exception e){Log.e(TAG,"Err saving content to: "+tf,e);em="Err saving: "+e.getMessage();}finally{try{if(o!=null)o.close();}catch(IOException ex){Log.e(TAG,"Err closing output save",ex);if(em==null)em="Err closing stream: "+ex.getMessage();}final boolean fo=ok;final String fm=em;mainThreadHandler.post(()->{setLoading(false);if(fo){Toast.makeText(this,"File saved!",Toast.LENGTH_SHORT).show();appendLog("✅ Save OK: "+tf);}else{String msg=(fm!=null)?fm:"Unknown save err.";Toast.makeText(this,msg,Toast.LENGTH_LONG).show();appendLog("❌ "+msg);}updateUiState();});}});}
    private void writeContentToStream(Object d,OutputStream o)throws IOException{if(d instanceof String){try(OutputStreamWriter w=new OutputStreamWriter(o,StandardCharsets.UTF_8)){w.write((String)d);w.flush();}}else if(d instanceof byte[]){try(BufferedOutputStream bo=new BufferedOutputStream(o)){bo.write((byte[])d);bo.flush();}}else if(d==null)throw new IOException("Cannot save null data.");else throw new IOException("Unsupp save type: "+d.getClass().getName());}

    private void updateUiState(){
        boolean apkP=selectedApkUri!=null&&tempApkPath!=null;
        boolean hP=extractedPackageName!=null&&!extractedPackageName.isEmpty();
        boolean hT=extractedTimestamp!=null;
        boolean mS=currentDataMode!=null;
        boolean load=progressBar.getVisibility()==View.VISIBLE;
        boolean iEO=currentOperation==MainActivity.OperationMode.ENCRYPT;
        boolean sAI=selectedApkUri!=null;

        tvPackageName.setVisibility(sAI?View.VISIBLE:View.GONE);
        tvTimestamp.setVisibility(sAI?View.VISIBLE:View.GONE);
        if(selectedApkUri!=null&&tvSelectedPathValue!=null){
            tvSelectedPathValue.setText(getFileNameFromUri(selectedApkUri));
            if(tvSelectedPathLabel!=null)tvSelectedPathLabel.setText("APK:");
        } else if(tvSelectedPathValue!=null){
            tvSelectedPathValue.setText("(None)");
            if(tvSelectedPathLabel!=null)tvSelectedPathLabel.setText("APK:");
        }

        // --- ENCRYPTION INPUTS VISIBILITY ---
        // Show only if Operation is Encrypt AND (DataMode is set) AND NOT Loading
        boolean showEncryptInputs = !load && iEO && mS;

        // Show/Hide the container logic
        // Note: I grouped input file and output dir into 'layoutEncryptionInputs' in XML to make this easier
        // But if 'layoutEncryptionInputs' doesn't exist in my variable (I need to check if I added it), I'll do it individually.
        // Checking my code above... I added `layoutEncryptionInputs` field and findView.
        if (layoutEncryptionInputs != null) {
            layoutEncryptionInputs.setVisibility(showEncryptInputs ? View.VISIBLE : View.GONE);
        } else {
             // Fallback if layout reference missed (though I added it)
            if(tvEncryptionInputLabel!=null) tvEncryptionInputLabel.setVisibility(showEncryptInputs?View.VISIBLE:View.GONE);
            if(btnSelectInputFile!=null) btnSelectInputFile.setVisibility(showEncryptInputs?View.VISIBLE:View.GONE);
            if(tvSelectedInputFilePath!=null) tvSelectedInputFilePath.setVisibility(showEncryptInputs?View.VISIBLE:View.GONE);
        }

        if(showEncryptInputs){
            String p="Select Plain Input File";
            if(currentDataMode!=null)switch(currentDataMode){
                case TIMESTAMP_DAT:p="Select Plain .dex";break;
                case CHAINED_PROPERTIES:p="Select Plain .properties";break;
                case CLONE_SETTINGS:p="Select Plain .json";break;
                case APP_DATA:p="Select Plain .zip";break;
                case SINGLE_PROPERTIES:p="Select Plain .properties";break;
            }
            btnSelectInputFile.setText(p);
            tvSelectedInputFilePath.setText(selectedInputFileUri!=null?"Input: "+getFileNameFromUri(selectedInputFileUri):"Input: (None)");

            // Check if Output Dir selection is needed
            boolean needOutputDir = (currentDataMode == MainActivity.DataMode.CHAINED_PROPERTIES || currentDataMode == MainActivity.DataMode.CLONE_SETTINGS);
            btnSelectEncryptOutputDir.setVisibility(needOutputDir?View.VISIBLE:View.GONE);
            tvSelectedEncryptOutputDirPath.setVisibility(needOutputDir?View.VISIBLE:View.GONE);

            if(needOutputDir){
                if (currentDataMode == MainActivity.DataMode.CLONE_SETTINGS) {
                    btnSelectEncryptOutputDir.setText("Select OutDir (Settings Chunks)");
                } else { // Chained Properties
                    btnSelectEncryptOutputDir.setText("Select OutDir (Chained Encrypt)");
                }
                tvSelectedEncryptOutputDirPath.setText(selectedEncryptOutputDirUri!=null?"OutDir: "+getDirNameFromTreeUri(selectedEncryptOutputDirUri):"OutDir: (None)");
            }
        }

        boolean cP=false;
        if(!load&&mS){
            boolean bM=apkP;
            // For decryption, we generally need the APK parsed for Package/TS
            if(requiresPackageName()&&!hP)bM=false;

            boolean tsRM=true;
            if(requiresTimestamp()){
                tsRM=hT;
            }
            if(!tsRM)bM=false;

            if(iEO){
                boolean eIM=selectedInputFileUri!=null;
                if((currentDataMode==MainActivity.DataMode.CHAINED_PROPERTIES || currentDataMode == MainActivity.DataMode.CLONE_SETTINGS) && selectedEncryptOutputDirUri==null)eIM=false;
                cP=bM&&eIM;
            } else cP=bM;
        }
        btnProcess.setEnabled(cP);

        boolean cS=currentSavableContent!=null&&!load;
        if(iEO && (currentDataMode == MainActivity.DataMode.CHAINED_PROPERTIES || currentDataMode == MainActivity.DataMode.CLONE_SETTINGS)) cS = false;
        btnSaveFile.setEnabled(cS);
    }

    private boolean requiresPackageName(){if(currentDataMode==null)return true;switch(currentDataMode){case TIMESTAMP_DAT:case CHAINED_PROPERTIES:case CLONE_SETTINGS:case APP_DATA:return true;default:return false;}}
    private boolean requiresTimestamp(){if(currentDataMode==null)return false;switch(currentDataMode){case TIMESTAMP_DAT:case CHAINED_PROPERTIES:return true;default:return false;}}
    private void setLoading(boolean l){
        mainThreadHandler.post(()->{
            progressBar.setVisibility(l?View.VISIBLE:View.GONE);
            boolean eUI=!l;
            btnSelectApkOrDir.setEnabled(eUI);
            setEnabledStateRadioGroup(radioGroupOperation,eUI);
            // Tab layout enable/disable
            if(tabLayoutMode != null) {
                for(int i=0; i < tabLayoutMode.getTabCount(); i++){
                    TabLayout.Tab tab = tabLayoutMode.getTabAt(i);
                    if(tab != null && tab.view != null) tab.view.setEnabled(eUI);
                }
            }

            btnSelectInputFile.setEnabled(eUI);
            btnSelectEncryptOutputDir.setEnabled(eUI);
            if(l){
                btnProcess.setEnabled(false);
                btnSaveFile.setEnabled(false);
            }else updateUiState();
        });
    }
    private void setEnabledStateRadioGroup(RadioGroup r,boolean e){for(int i=0;i<r.getChildCount();i++){View c=r.getChildAt(i);if(c instanceof RadioButton)c.setEnabled(e);}}
    private void clearLog(){mainThreadHandler.post(()->{if(tvLogOutput!=null)tvLogOutput.setText("");});}
    private void appendLog(String m){final String tM=new SimpleDateFormat("HH:mm:ss.SSS",Locale.US).format(new Date())+": "+m;mainThreadHandler.post(()->{if(tvLogOutput!=null){tvLogOutput.append(tM+"\n");try{final int s=tvLogOutput.getLayout().getLineTop(tvLogOutput.getLineCount())-tvLogOutput.getHeight();if(s>0)tvLogOutput.scrollTo(0,s);else tvLogOutput.scrollTo(0,0);}catch(Exception e){Log.w(TAG,"Log scroll err: "+e.getMessage());}}Log.d(TAG,m);});}
    private void showError(String m){Toast.makeText(this,m,Toast.LENGTH_LONG).show();appendLog("❌ ERROR: "+m);}
    private void clearSourceData(boolean cA){selectedApkUri=null;deleteTempApkFile();if(tvSelectedPathLabel!=null)tvSelectedPathLabel.setText("APK:");if(tvSelectedPathValue!=null)tvSelectedPathValue.setText("(None)");if(tvPackageName!=null){tvPackageName.setText("Package: ");tvPackageName.setVisibility(View.GONE);}if(tvTimestamp!=null){tvTimestamp.setText("Timestamp: ");tvTimestamp.setVisibility(View.GONE);}
    extractedPackageName=null;extractedTimestamp=null;currentSavableContent=null;if(cA){selectedInputFileUri=null;selectedEncryptOutputDirUri=null;if(tvSelectedInputFilePath!=null)tvSelectedInputFilePath.setText("Input: (None)");if(tvSelectedEncryptOutputDirPath!=null)tvSelectedEncryptOutputDirPath.setText("OutDir: (None)");}updateUiState();}
    private String getFileNameFromUri(Uri u){if(u==null)return"Unknown_File";String r=null;try{DocumentFile d=DocumentFile.fromSingleUri(this,u);if(d!=null&&d.getName()!=null)return d.getName();}catch(Exception e){Log.w(TAG,"DocFile name fail: "+e.getMessage());}if(ContentResolver.SCHEME_CONTENT.equals(u.getScheme())){android.database.Cursor c=null;try{c=getContentResolver().query(u,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null);if(c!=null&&c.moveToFirst()){int n=c.getColumnIndex(OpenableColumns.DISPLAY_NAME);if(n!=-1)r=c.getString(n);}}catch(Exception e){Log.w(TAG,"ContentResolver query name fail: "+e.getMessage());}finally{if(c!=null)c.close();}}if(r==null){r=u.getPath();if(r!=null){int ct=r.lastIndexOf('/');if(ct!=-1)r=r.substring(ct+1);}}if(r!=null&&r.contains("%"))try{r=Uri.decode(r);}catch(Exception ig){}return(r!=null&&!r.isEmpty())?r:u.getLastPathSegment()!=null?u.getLastPathSegment():"Unnamed_File";}
    private String getDirNameFromTreeUri(Uri tU){if(tU==null)return"Unknown_Dir";try{DocumentFile d=DocumentFile.fromTreeUri(this,tU);if(d!=null&&d.getName()!=null)return d.getName();String dI=DocumentsContract.getTreeDocumentId(tU);if(dI!=null){int c=dI.lastIndexOf(':');if(c!=-1&&c<dI.length()-1)return Uri.decode(dI.substring(c+1));else if(!dI.isEmpty())return Uri.decode(dI);}String lS=tU.getLastPathSegment();if(lS!=null){int c=lS.lastIndexOf(':');if(c!=-1&&c<lS.length()-1)return Uri.decode(lS.substring(c+1));return Uri.decode(lS);}}catch(Exception e){Log.e(TAG,"Err getDirName TreeUri",e);}return tU.getLastPathSegment()!=null?Uri.decode(tU.getLastPathSegment()):"Unnamed_Dir";}
    private String generateSuggestedFilename(SavableContent c){SimpleDateFormat s=new SimpleDateFormat("yyyyMMdd_HHmmss",Locale.US);String ts=s.format(new Date());String b="file";String o=(c.operationPerformed==MainActivity.OperationMode.DECRYPT)?"_dec":"_enc";String x=".bin";if(c.inputFilename!=null&&!c.inputFilename.isEmpty()&&!c.inputFilename.startsWith("err_")){int l=c.inputFilename.lastIndexOf('.');if(l>0)b=c.inputFilename.substring(0,l);else b=c.inputFilename;}else{b=c.targetMode.name().toLowerCase(Locale.US);if(c.packageName!=null&&!c.packageName.isEmpty()){String sp=c.packageName.substring(c.packageName.lastIndexOf('.')+1);b+="_"+sp;}}switch(c.targetMode){case TIMESTAMP_DAT:x=(c.operationPerformed==MainActivity.OperationMode.DECRYPT)?".dex":".dat";break;case CHAINED_PROPERTIES:if(c.operationPerformed==MainActivity.OperationMode.DECRYPT){b="strings_"+(c.packageName!=null?c.packageName.replace('.','_'):"unk");x=".properties";}else{b="chained_sum";x=".txt";}break;case CLONE_SETTINGS:b="cloneSettings_"+(c.packageName!=null?c.packageName.replace('.','_'):"unk");x=".json";break;case APP_DATA:b=(c.packageName!=null?c.packageName.replace('.','_'):"app")+"_data";x=(c.operationPerformed==MainActivity.OperationMode.DECRYPT)?".zip":".app_data";break;case LEGACY_STRINGS_PROPERTIES:b="strings_legacy";x=".properties";break;}}b=b.replaceAll("[^a-zA-Z0-9._-]","_");if(b.length()>50)b=b.substring(0,50);return b+o+"_"+ts+x;}
    private boolean isValidZipData(byte[]d){if(d==null||d.length<4)return false;if(!(d[0]==0x50&&d[1]==0x4B&&d[2]==0x03&&d[3]==0x04))return false;ZipInputStream z=null;try{z=new ZipInputStream(new ByteArrayInputStream(d));return z.getNextEntry()!=null;}catch(Exception e){Log.d(TAG,"isValidZip check fail entry: "+e.getMessage());return false;}finally{if(z!=null)try{z.close();}catch(IOException ig){}}}
    private void clearPersistedPermissions(){List<android.content.UriPermission>ps=getContentResolver().getPersistedUriPermissions();if(!ps.isEmpty()){appendLog("Clearing "+ps.size()+" persisted URI perms...");int r=0;for(android.content.UriPermission p:ps){try{getContentResolver().releasePersistableUriPermission(p.getUri(),Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION);r++;}catch(SecurityException e){appendLog("⚠️ Failed release perm URI: "+getFileNameFromUri(p.getUri())+" - "+e.getMessage());}}if(r>0)appendLog("Released "+r+" persisted URI perms.");}}

}