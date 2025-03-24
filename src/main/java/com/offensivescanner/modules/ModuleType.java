package com.offensivescanner.modules;

/**
 * Enumeration of module types for the scanner.
 * Each module type corresponds to a specific scanning functionality.
 */
public enum ModuleType {
    PORT_SCANNING("Port Scanning", "Scans for open ports on target hosts"),
    SERVICE_ENUMERATION("Service Enumeration", "Enumerates services running on open ports"),
    WEB_SCANNING("Web Scanning", "Scans for web vulnerabilities and misconfigurations"),
    VULNERABILITY_SCANNING("Vulnerability Scanning", "Scans for common security vulnerabilities"),
    NETWORK_DISCOVERY("Network Discovery", "Discovers hosts and network topology"),
    BRUTE_FORCE("Brute Force", "Attempts to brute force credentials for services"),
    DNS_ENUMERATION("DNS Enumeration", "Enumerates DNS records and subdomains"),
    SSL_ANALYSIS("SSL/TLS Analysis", "Analyzes SSL/TLS configurations for weaknesses"),
    EXPLOITATION("Exploitation", "Exploits vulnerabilities for proof-of-concept");
    
    private final String displayName;
    private final String description;
    
    /**
     * Create a new module type
     * 
     * @param displayName The display name of the module type
     * @param description The description of the module type
     */
    ModuleType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    /**
     * Get the display name of this module type
     * 
     * @return The display name
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * Get the description of this module type
     * 
     * @return The description
     */
    public String getDescription() {
        return description;
    }
    
    @Override
    public String toString() {
        return displayName;
    }
} 