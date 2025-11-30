package com.appkloner.tool;

/**
 * Enumeration of data modes supported by the AppCloner Tool.
 * Each mode represents a different type of encrypted data that can be processed.
 */
public enum DataMode {
    /** Timestamp-based DAT file (app_cloner.dat) */
    TIMESTAMP_DAT,
    
    /** Chained properties files (multiple encrypted property files) */
    CHAINED_PROPERTIES,
    
    /** Clone settings (JSON configuration split into chunks) */
    CLONE_SETTINGS,
    
    /** App data (ZIP archives with XOR or AES encryption) */
    APP_DATA,
    
    /** Single properties file (legacy, no longer used in new versions) */
    SINGLE_PROPERTIES,
    
    /** Legacy strings.properties file (old AppCloner versions) */
    LEGACY_STRINGS_PROPERTIES
}