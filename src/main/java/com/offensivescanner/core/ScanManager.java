package com.offensivescanner.core;

import com.offensivescanner.modules.*;
import com.offensivescanner.modules.port.PortScanner;
import com.offensivescanner.modules.service.ServiceEnumerator;
import com.offensivescanner.modules.web.WebScanner;
import com.offensivescanner.modules.vuln.VulnerabilityScanner;
import com.offensivescanner.modules.network.NetworkScanner;
import com.offensivescanner.modules.brute.BruteForceScanner;
import com.offensivescanner.modules.dns.DNSScanner;
import com.offensivescanner.modules.ssl.SSLScanner;
import com.offensivescanner.modules.exploit.ExploitScanner;
import com.offensivescanner.reporting.ReportGenerator;
import com.offensivescanner.utils.ConsoleUtils;

import java.util.Set;
/**
 * Manages the scanning process, initializing and coordinating the various scan modules.
 */
public class ScanManager {

    private final ConfigManager configManager;
    private final Target target;
    private final Set<ModuleType> enabledModules;
    private final ScanResults scanResults;
    
    // Module instances
    private PortScanner portScanner;
    private ServiceEnumerator serviceEnumerator;
    private WebScanner webScanner;
    private VulnerabilityScanner vulnerabilityScanner;
    private NetworkScanner networkScanner;
    private BruteForceScanner bruteForceScanner;
    private DNSScanner dnsScanner;
    private SSLScanner sslScanner;
    private ExploitScanner exploitScanner;
    
    /**
     * Create a new scan manager
     * 
     * @param configManager The configuration manager
     * @param target The target to scan
     * @param enabledModules The set of enabled module types
     */
    public ScanManager(ConfigManager configManager, Target target, Set<ModuleType> enabledModules) {
        this.configManager = configManager;
        this.target = target;
        this.enabledModules = enabledModules;
        this.scanResults = new ScanResults(target);
        
        // Initialize modules
        initializeModules();
    }
    
    /**
     * Create a new scan manager with provided scan results
     * 
     * @param configManager The configuration manager
     * @param target The target to scan
     * @param enabledModules The set of enabled module types
     * @param scanResults The scan results container
     */
    public ScanManager(ConfigManager configManager, Target target, Set<ModuleType> enabledModules, ScanResults scanResults) {
        this.configManager = configManager;
        this.target = target;
        this.enabledModules = enabledModules;
        this.scanResults = scanResults;
        
        // Set the target in scan results if not already set
        if (scanResults.getTarget() == null) {
            scanResults.setTarget(target);
        }
        
        // Initialize modules
        initializeModules();
    }
    
    /**
     * Initialize the enabled scan modules
     */
    private void initializeModules() {
        if (isModuleEnabled(ModuleType.PORT_SCANNING)) {
            portScanner = new PortScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.SERVICE_ENUMERATION)) {
            serviceEnumerator = new ServiceEnumerator(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.WEB_SCANNING)) {
            webScanner = new WebScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.VULNERABILITY_SCANNING)) {
            vulnerabilityScanner = new VulnerabilityScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.NETWORK_DISCOVERY)) {
            networkScanner = new NetworkScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.BRUTE_FORCE)) {
            bruteForceScanner = new BruteForceScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.DNS_ENUMERATION)) {
            dnsScanner = new DNSScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.SSL_ANALYSIS)) {
            sslScanner = new SSLScanner(configManager, scanResults);
        }
        
        if (isModuleEnabled(ModuleType.EXPLOITATION)) {
            exploitScanner = new ExploitScanner(configManager, scanResults);
        }
    }
    
    /**
     * Check if a module type is enabled
     * 
     * @param moduleType The module type to check
     * @return true if the module is enabled
     */
    private boolean isModuleEnabled(ModuleType moduleType) {
        return enabledModules.contains(moduleType);
    }
    
    /**
     * Run the scan with all enabled modules
     * 
     * @throws Exception if an error occurs during scanning
     */
    public void runScan() throws Exception {
        ConsoleUtils.printInfo("Starting scan against " + target.toString());
        
        // Record scan start time
        scanResults.setScanStartTime(System.currentTimeMillis());
        
        // Run the modules in the appropriate order based on dependencies
        // 1. First run network discovery to find hosts
        if (isModuleEnabled(ModuleType.NETWORK_DISCOVERY)) {
            ConsoleUtils.printInfo("Running network discovery...");
            networkScanner.scan(target);
        }
        
        // 2. Run DNS enumeration
        if (isModuleEnabled(ModuleType.DNS_ENUMERATION)) {
            ConsoleUtils.printInfo("Running DNS enumeration...");
            dnsScanner.scan(target);
        }
        
        // 3. Run port scan to find open ports
        if (isModuleEnabled(ModuleType.PORT_SCANNING)) {
            ConsoleUtils.printInfo("Running port scan...");
            portScanner.scan(target);
        }
        
        // 4. Run service enumeration to identify services on open ports
        if (isModuleEnabled(ModuleType.SERVICE_ENUMERATION)) {
            ConsoleUtils.printInfo("Running service enumeration...");
            serviceEnumerator.scan(target);
        }
        
        // 5. Run SSL/TLS analysis on compatible services
        if (isModuleEnabled(ModuleType.SSL_ANALYSIS)) {
            ConsoleUtils.printInfo("Running SSL/TLS analysis...");
            sslScanner.scan(target);
        }
        
        // 6. Run web scanning on web servers
        if (isModuleEnabled(ModuleType.WEB_SCANNING)) {
            ConsoleUtils.printInfo("Running web scanning...");
            webScanner.scan(target);
        }
        
        // 7. Run vulnerability scanning
        if (isModuleEnabled(ModuleType.VULNERABILITY_SCANNING)) {
            ConsoleUtils.printInfo("Running vulnerability scanning...");
            vulnerabilityScanner.scan(target);
        }
        
        // 8. Run brute force attacks
        if (isModuleEnabled(ModuleType.BRUTE_FORCE)) {
            ConsoleUtils.printInfo("Running brute force attacks...");
            bruteForceScanner.scan(target);
        }
        
        // 9. Run exploitation modules (if enabled - this should be used with caution)
        if (isModuleEnabled(ModuleType.EXPLOITATION)) {
            ConsoleUtils.printInfo("Running exploitation modules...");
            exploitScanner.scan(target);
        }
        
        // Record scan end time
        scanResults.setScanEndTime(System.currentTimeMillis());
        
        // Display summary of findings
        displayScanSummary();
    }
    
    /**
     * Display a summary of the scan results
     */
    private void displayScanSummary() {
        ConsoleUtils.printSuccess("Scan completed in " + formatDuration(scanResults.getScanDuration()));
        
        // Display vulnerability summary
        int criticalVulns = scanResults.getVulnerabilityCount(VulnerabilitySeverity.CRITICAL);
        int highVulns = scanResults.getVulnerabilityCount(VulnerabilitySeverity.HIGH);
        int mediumVulns = scanResults.getVulnerabilityCount(VulnerabilitySeverity.MEDIUM);
        int lowVulns = scanResults.getVulnerabilityCount(VulnerabilitySeverity.LOW);
        int infoVulns = scanResults.getVulnerabilityCount(VulnerabilitySeverity.INFO);
        
        ConsoleUtils.printInfo("Vulnerability Summary:");
        ConsoleUtils.printError("  Critical: " + criticalVulns);
        ConsoleUtils.printWarning("  High: " + highVulns);
        ConsoleUtils.printWarning("  Medium: " + mediumVulns);
        ConsoleUtils.printInfo("  Low: " + lowVulns);
        ConsoleUtils.printInfo("  Informational: " + infoVulns);
        
        // Display open ports summary
        int openPorts = scanResults.getOpenPortCount();
        ConsoleUtils.printInfo("Open Ports: " + openPorts);
        
        // Display web vulnerabilities if relevant
        if (isModuleEnabled(ModuleType.WEB_SCANNING)) {
            int webVulns = scanResults.getWebVulnerabilityCount();
            ConsoleUtils.printInfo("Web Vulnerabilities: " + webVulns);
        }
    }
    
    /**
     * Format duration in milliseconds to a human-readable string
     * 
     * @param durationMs Duration in milliseconds
     * @return Formatted duration string
     */
    private String formatDuration(long durationMs) {
        long seconds = durationMs / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        
        seconds %= 60;
        minutes %= 60;
        
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }
    
    /**
     * Generate reports for the scan results
     * 
     * @param reportDir The directory to store reports
     * @throws Exception if an error occurs
     */
    public void generateReports(String reportDir) throws Exception {
        ConsoleUtils.printSectionHeader("Generating Reports");
        
        // Create a report generator and generate reports
        ReportGenerator reportGenerator = new ReportGenerator(configManager, scanResults);
        reportGenerator.generateReports(reportDir);
        
        ConsoleUtils.printSuccess("Reports generated successfully in " + reportDir);
    }
    
    /**
     * Get the scan results
     * 
     * @return The scan results
     */
    public ScanResults getScanResults() {
        return scanResults;
    }
} 