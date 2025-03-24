package com.offensivescanner.core;

import org.yaml.snakeyaml.Yaml;
import com.offensivescanner.utils.ConsoleUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * ConfigManager loads and manages configuration settings for the scanner.
 * Supports YAML configuration format.
 */
public class ConfigManager {
    
    private static final String DEFAULT_CONFIG_PATH = "src/main/resources/config.yml";
    private Map<String, Object> config = new HashMap<>();
    
    /**
     * Create a new ConfigManager with default configuration path
     */
    public ConfigManager() {
        // Default constructor, will use default config path
    }
    
    /**
     * Load configuration from the default file path
     * 
     * @throws IOException if the configuration file cannot be read
     */
    public void loadDefaultConfig() throws IOException {
        loadConfig(DEFAULT_CONFIG_PATH);
    }
    
    /**
     * Load configuration from a specified file path
     * 
     * @param configPath Path to the configuration file
     * @throws IOException if the configuration file cannot be read
     */
    public void loadConfig(String configPath) throws IOException {
        File configFile = new File(configPath);
        if (!configFile.exists() || !configFile.isFile()) {
            throw new IOException("Configuration file not found: " + configPath);
        }
        
        try (InputStream inputStream = new FileInputStream(configFile)) {
            Yaml yaml = new Yaml();
            Object loaded = yaml.load(inputStream);
            
            if (loaded instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> loadedMap = (Map<String, Object>) loaded;
                config = loadedMap;
                ConsoleUtils.printVerbose("Loaded configuration from " + configPath);
            } else {
                throw new IOException("Invalid configuration format in " + configPath);
            }
        } catch (Exception e) {
            throw new IOException("Error loading configuration: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get a configuration value for a specific section and key
     * 
     * @param <T> The type of the configuration value
     * @param section The configuration section
     * @param key The configuration key
     * @param defaultValue The default value to return if the key is not found
     * @return The configuration value or the default value
     */
    @SuppressWarnings("unchecked")
    public <T> T getConfigValue(String section, String key, T defaultValue) {
        if (!config.containsKey(section)) {
            return defaultValue;
        }
        
        Object sectionObj = config.get(section);
        if (!(sectionObj instanceof Map)) {
            return defaultValue;
        }
        
        Map<String, Object> sectionMap = (Map<String, Object>) sectionObj;
        if (!sectionMap.containsKey(key)) {
            return defaultValue;
        }
        
        Object value = sectionMap.get(key);
        
        // Make sure the type matches
        if (defaultValue != null && value != null && 
            defaultValue.getClass().isAssignableFrom(value.getClass())) {
            return (T) value;
        } else if (defaultValue instanceof Integer && value instanceof Number) {
            return (T) Integer.valueOf(((Number) value).intValue());
        } else if (defaultValue instanceof Long && value instanceof Number) {
            return (T) Long.valueOf(((Number) value).longValue());
        } else if (defaultValue instanceof Double && value instanceof Number) {
            return (T) Double.valueOf(((Number) value).doubleValue());
        } else if (defaultValue instanceof Boolean && value instanceof Boolean) {
            return (T) value;
        } else if (defaultValue instanceof String && value instanceof String) {
            return (T) value;
        }
        
        return defaultValue;
    }
    
    /**
     * Set a configuration value for a specific section and key
     * 
     * @param <T> The type of the configuration value
     * @param section The configuration section
     * @param key The configuration key
     * @param value The value to set
     */
    @SuppressWarnings("unchecked")
    public <T> void setConfigValue(String section, String key, T value) {
        if (!config.containsKey(section)) {
            config.put(section, new HashMap<String, Object>());
        }
        
        Object sectionObj = config.get(section);
        if (!(sectionObj instanceof Map)) {
            config.put(section, new HashMap<String, Object>());
            sectionObj = config.get(section);
        }
        
        Map<String, Object> sectionMap = (Map<String, Object>) sectionObj;
        sectionMap.put(key, value);
    }
    
    /**
     * Get the entire configuration map
     * 
     * @return Unmodifiable view of the configuration map
     */
    public Map<String, Object> getConfig() {
        return Collections.unmodifiableMap(config);
    }
    
    /**
     * Get a section of the configuration
     * 
     * @param section The section name
     * @return Map containing the section's configuration or empty map if not found
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getSection(String section) {
        if (!config.containsKey(section)) {
            return Collections.emptyMap();
        }
        
        Object sectionObj = config.get(section);
        if (!(sectionObj instanceof Map)) {
            return Collections.emptyMap();
        }
        
        return Collections.unmodifiableMap((Map<String, Object>) sectionObj);
    }
} 