package com.appkloner.tool;

/**
 * Enumeration of operation modes supported by the AppCloner Tool.
 * Defines whether to encrypt or decrypt data.
 */
public enum OperationMode {
    /** Decrypt operation - extract and decrypt data from APK */
    DECRYPT,
    
    /** Encrypt operation - encrypt plain data for injection into APK */
    ENCRYPT
}