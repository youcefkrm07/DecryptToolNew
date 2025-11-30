package com.appkloner.tool;

import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter; // Added for UTF-8 saving
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap; // Preserve insertion order for potential consistency
import java.util.Map;
import java.util.Locale;
import java.util.Properties; // Can use standard Java Properties for parsing/loading
import java.util.stream.Collectors;

public final class PropertiesParser {

    private static final String TAG = "PropertiesParser";

    private PropertiesParser() {} // Prevent instantiation

    /**
     * Parses Java properties from a byte array.
     * Uses standard java.util.Properties for robustness.
     * Tries UTF-8 first, then falls back to ISO-8859-1.
     */
    public static Map<String, String> parseProperties(byte[] data) {
        // Use LinkedHashMap to maintain order similar to reading file lines
        Map<String, String> propertiesMap = new LinkedHashMap<>();
        Properties properties = new Properties();
        BufferedReader readerUtf8 = null;
        BufferedReader readerIso = null;
        boolean parsed = false;

        // Try UTF-8 first as it's common
        try {
            readerUtf8 = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data), StandardCharsets.UTF_8));
            properties.load(readerUtf8);
             // Check if parsing resulted in properties (heuristic for correct encoding)
             if (!properties.isEmpty()) {
                 Log.d(TAG, "Parsed properties using UTF-8.");
                 parsed = true;
             } else if (data != null && data.length > 0) { // Only try ISO if UTF-8 yielded nothing but there was data
                 Log.d(TAG, "UTF-8 parsing yielded no properties from non-empty data, trying ISO-8859-1.");
             } else {
                 Log.d(TAG, "UTF-8 parsing yielded no properties (data was likely empty).");
                 // If data is empty, parsed is false, but we don't need to try ISO.
                 // If data is null or empty, properties.isEmpty() will be true, this path is fine.
             }
        } catch (IllegalArgumentException iae) {
            // This can happen with malformed Unicode escape sequences if using Properties.load
            Log.w(TAG, "Warning parsing properties with UTF-8: Malformed input? " + iae.getMessage());
            // Clear any potentially partially loaded properties from the error
            properties.clear();
            Log.d(TAG,"Attempting ISO-8859-1 after UTF-8 parse error.");
        } catch (IOException e) {
            Log.e(TAG, "IOException parsing properties with UTF-8: " + e.getMessage(), e);
            properties.clear(); // Clear potentially partial load
            Log.d(TAG,"Attempting ISO-8859-1 after UTF-8 IO error.");
        } finally {
             if (readerUtf8 != null) {
                 try { readerUtf8.close(); } catch (IOException ignored) {}
             }
        }

        // If UTF-8 failed or yielded nothing from non-empty data, try ISO-8859-1
        if (!parsed && data != null && data.length > 0) { // Added check for data not null/empty
             try {
                 // Ensure properties object is clear before trying ISO
                 properties.clear();
                 readerIso = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data), StandardCharsets.ISO_8859_1));
                 properties.load(readerIso);
                 if (!properties.isEmpty()) {
                    Log.d(TAG, "Parsed properties using ISO-8859-1.");
                    // parsed = true; // Not strictly needed anymore as we won't try another encoding
                 } else {
                     Log.w(TAG, "Failed to parse properties with ISO-8859-1 as well (or file empty/non-properties format).");
                 }
             } catch (Exception e) { // Catch generic Exception for ISO fallback
                 Log.e(TAG, "Error parsing properties with ISO-8859-1 fallback: " + e.getMessage(), e);
             } finally {
                  if (readerIso != null) {
                      try { readerIso.close(); } catch (IOException ignored) {}
                  }
             }
        }

        // Convert Properties object (might be Hashtable internally) to a standard Map<String, String>
        // Using entrySet is slightly more efficient than stringPropertyNames + getProperty
        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            // Properties keys/values are Objects, but should be Strings
            if (entry.getKey() instanceof String && entry.getValue() instanceof String) {
                 propertiesMap.put((String)entry.getKey(), (String)entry.getValue());
            } else if (entry.getKey() != null && entry.getValue() != null) {
                 // Attempt to convert to string if not null, log warning
                 String keyStr = entry.getKey().toString();
                 String valStr = entry.getValue().toString();
                 propertiesMap.put(keyStr, valStr);
                 Log.w(TAG, "Converted non-string property to string (Key type: "
                         + entry.getKey().getClass().getSimpleName() + " -> '" + keyStr + "'"
                         + ", Value type: " + entry.getValue().getClass().getSimpleName() + " -> '" + valStr + "')");
            } else {
                Log.w(TAG, "Skipping null key or value in properties.");
            }
        }
        if (propertiesMap.isEmpty() && data != null && data.length > 0) {
             Log.w(TAG, "parseProperties returning empty map despite non-empty input data. Input may not be valid properties format or uses an unsupported encoding.");
        }
        return propertiesMap;
    }

    /**
     * Formats properties into a string suitable for saving, with comments.
     * Uses java.util.Properties.store() for correct escaping.
     * Ensures UTF-8 output and sorts keys for consistency.
     */
    public static String formatProperties(Map<String, String> propertiesMap) {
        // Create a Properties object to leverage its store method
        Properties properties = new Properties();

        // Create a sorted version for consistent output
        // The Properties class itself doesn't guarantee order, but store() might iterate
        // using keys(). So, we provide an overridden Properties instance that sorts keys.
        Properties sortedProps = new Properties() {
            // Override keys() to return sorted keys
            @Override
            public synchronized java.util.Enumeration<Object> keys() {
                return java.util.Collections.enumeration(
                        super.keySet().stream() // Use super to get the actual keys from the backing Hashtable
                                .map(Object::toString)
                                .sorted()
                                .collect(Collectors.toList())
                );
            }

            // It's also good practice to override entrySet if we expect sorted iteration,
            // though store() in OpenJDK typically uses keys().
            @Override
            public java.util.Set<Map.Entry<Object, Object>> entrySet() {
                java.util.Set<Map.Entry<Object, Object>> sortedEntries = new java.util.LinkedHashSet<>(super.size());
                // Use the sorted keys enumeration to build a LinkedHashSet maintaining order
                this.keys().asIterator().forEachRemaining(key -> { // 'this.keys()' calls our overridden sorted keys()
                    sortedEntries.add(new java.util.AbstractMap.SimpleEntry<>(key, super.get(key)));
                });
                return sortedEntries;
            }

            // Override stringPropertyNames() as well for completeness, ensuring sorted output.
            @Override
            public java.util.Set<String> stringPropertyNames() {
                 return super.keySet().stream()
                                .map(Object::toString)
                                .sorted()
                                .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
            }
        };
        // Load the map into the Properties object *before* putting into sortedProps
        // This is important: sortedProps must have the data when its overridden methods are called.
        sortedProps.putAll(propertiesMap);


        // Generate timestamp comment
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(new Date());
        String comments = "# Properties Export - " + timestamp + "\n# Total: " + propertiesMap.size();

        // Use Properties.store() with an OutputStreamWriter to control encoding
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             OutputStreamWriter osw = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {

            // Store using the UTF-8 writer and the sorted Properties object
            sortedProps.store(osw, comments); // Pass our sortedProps instance
            osw.flush(); // Ensure all data is written to the underlying stream
            return baos.toString(StandardCharsets.UTF_8.name()); // Use charset name for clarity

        } catch (IOException e) {
            Log.e(TAG, "Error formatting properties to string using Properties.store()", e);
            // Fallback to basic manual formatting if store fails (less reliable escaping)
            StringBuilder sb = new StringBuilder();
            sb.append(comments).append("\n\n");
            propertiesMap.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey()) // Ensure fallback is also sorted
                    .forEach(entry -> sb.append(escapePropertyKey(entry.getKey()))
                                        .append(" = ") // Add space around '=' for readability
                                        .append(escapePropertyValue(entry.getValue()))
                                        .append("\n"));
            return sb.toString();
        }
    }

    // Manual escaping needed only if Properties.store() fails (basic implementation)
    private static String escapePropertyKey(String key) {
        if (key == null) return "";
        // Basic escaping for key characters: \, =, :, #, !, and space
        return key.replace("\\", "\\\\")
                  .replace("=", "\\=")
                  .replace(":", "\\:")
                  .replace("#", "\\#")
                  .replace("!", "\\!")
                  .replace(" ", "\\ ");
    }

    // Manual escaping needed only if Properties.store() fails (basic implementation)
    private static String escapePropertyValue(String value) {
        if (value == null) return "";
        // Basic escaping for value characters: \, newline, carriage return
        // Also leading spaces for values.
        String escaped = value.replace("\\", "\\\\")
                              .replace("\n", "\\n")
                              .replace("\r", "\\r"); // Corrected to escape \r
        if (escaped.startsWith(" ")) {
            escaped = "\\ " + escaped.substring(1);
        }
        return escaped;
    }
}