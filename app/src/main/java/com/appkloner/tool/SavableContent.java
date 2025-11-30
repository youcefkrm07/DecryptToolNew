package com.appkloner.tool;

/**
 * Container class for savable content after encryption or decryption operations.
 * 
 * This class holds the processed data along with metadata needed for
 * proper filename generation and file saving operations.
 */
public class SavableContent {
    
    /** The processed data - can be String or byte[] */
    public final Object data;
    
    /** The data mode that was processed */
    public final DataMode targetMode;
    
    /** The operation that was performed (encrypt or decrypt) */
    public final OperationMode operationPerformed;
    
    /** Package name from APK (can be null) */
    public final String packageName;
    
    /** Original input filename (can be null) */
    public final String inputFilename;

    /**
     * Creates a new SavableContent instance.
     * 
     * @param data The processed data (String or byte[])
     * @param targetMode The data mode that was processed
     * @param operationPerformed The operation that was performed
     * @param packageName The package name from APK (can be null)
     * @param inputFilename The original input filename (can be null)
     * @throws IllegalArgumentException if data type is unsupported
     */
    public SavableContent(Object data, DataMode targetMode, OperationMode operationPerformed, 
                         String packageName, String inputFilename) {
        // Validate data type
        if (!(data instanceof String || data instanceof byte[] || data == null)) {
             throw new IllegalArgumentException(
                 "Unsupported data type for SavableContent: " + data.getClass().getName());
        }
        
        // Allow null data only for modes that don't generate single file output
        // (e.g., CHAINED_PROPERTIES and CLONE_SETTINGS encryption save multiple files directly)
        if (data == null) {
            boolean allowNull = (targetMode == DataMode.CHAINED_PROPERTIES || 
                                targetMode == DataMode.CLONE_SETTINGS) && 
                               operationPerformed == OperationMode.ENCRYPT;
            if (!allowNull) {
                throw new IllegalArgumentException(
                    "Null data not allowed for mode: " + targetMode + 
                    " with operation: " + operationPerformed);
            }
        }

        this.data = data;
        this.targetMode = targetMode;
        this.operationPerformed = operationPerformed;
        this.packageName = packageName;
        this.inputFilename = inputFilename;
    }
}