package com.offensivescanner.modules;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.utils.ConsoleUtils;

/**
 * Abstract base class for all scanner modules.
 * Provides common functionality for scanner modules.
 */
public abstract class AbstractScanModule implements ScanModule {
    
    protected final ConfigManager configManager;
    protected final ScanResults scanResults;
    protected final String name;
    protected final String description;
    protected final ModuleType type;
    
    /**
     * Create a new scanner module
     * 
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     * @param name The module name
     * @param description The module description
     * @param type The module type
     */
    public AbstractScanModule(ConfigManager configManager, ScanResults scanResults, 
                             String name, String description, ModuleType type) {
        this.configManager = configManager;
        this.scanResults = scanResults;
        this.name = name;
        this.description = description;
        this.type = type;
    }
    
    @Override
    public String getName() {
        return name;
    }
    
    @Override
    public String getDescription() {
        return description;
    }
    
    @Override
    public ModuleType getType() {
        return type;
    }
    
    /**
     * Log an informational message for this module
     * 
     * @param message The message to log
     */
    protected void logInfo(String message) {
        ConsoleUtils.printInfo("[" + name + "] " + message);
    }
    
    /**
     * Log a success message for this module
     * 
     * @param message The message to log
     */
    protected void logSuccess(String message) {
        ConsoleUtils.printSuccess("[" + name + "] " + message);
    }
    
    /**
     * Log an error message for this module
     * 
     * @param message The message to log
     */
    protected void logError(String message) {
        ConsoleUtils.printError("[" + name + "] " + message);
    }
    
    /**
     * Log a warning message for this module
     * 
     * @param message The message to log
     */
    protected void logWarning(String message) {
        ConsoleUtils.printWarning("[" + name + "] " + message);
    }
    
    /**
     * Log a debug message for this module (only shown in debug mode)
     * 
     * @param message The message to log
     */
    protected void logDebug(String message) {
        if (isDebugEnabled()) {
            ConsoleUtils.printDebug("[" + name + "] " + message);
        }
    }
    
    /**
     * Log a verbose message for this module (only shown in verbose mode)
     * 
     * @param message The message to log
     */
    protected void logVerbose(String message) {
        if (isVerboseEnabled()) {
            ConsoleUtils.printVerbose("[" + name + "] " + message);
        }
    }
    
    /**
     * Check if debug mode is enabled
     * 
     * @return true if debug mode is enabled
     */
    protected boolean isDebugEnabled() {
        return configManager.getConfigValue("general", "debug", false);
    }
    
    /**
     * Check if verbose mode is enabled
     * 
     * @return true if verbose mode is enabled
     */
    protected boolean isVerboseEnabled() {
        return configManager.getConfigValue("general", "verbose", false);
    }
    
    /**
     * Get the default timeout from configuration
     * 
     * @return The default timeout in seconds
     */
    protected int getDefaultTimeout() {
        return configManager.getConfigValue("general", "timeout", 30);
    }
} 