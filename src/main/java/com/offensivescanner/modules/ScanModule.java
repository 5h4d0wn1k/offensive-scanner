package com.offensivescanner.modules;

import com.offensivescanner.core.Target;

/**
 * Interface for all scanner modules.
 * Defines the common methods that all scanner modules must implement.
 */
public interface ScanModule {
    
    /**
     * Scan the specified target
     * 
     * @param target The target to scan
     * @throws Exception if an error occurs during scanning
     */
    void scan(Target target) throws Exception;
    
    /**
     * Get the name of this module
     * 
     * @return The module name
     */
    String getName();
    
    /**
     * Get the description of this module
     * 
     * @return The module description
     */
    String getDescription();
    
    /**
     * Get the type of this module
     * 
     * @return The module type
     */
    ModuleType getType();
} 