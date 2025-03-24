package com.offensivescanner;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.modules.ModuleType;
import com.offensivescanner.utils.ConsoleUtils;
import org.apache.commons.cli.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Main class for the Offensive Scanner application.
 * Handles command-line arguments and orchestrates the scanning process.
 */
public class OffensiveScanner {
    
    private static final String APP_NAME = "Offensive Scanner";
    private static final String VERSION = "1.0-SNAPSHOT";
    
    private final ConfigManager configManager;
    private final List<Target> targets = new ArrayList<>();
    
    /**
     * Main method - entry point for the application
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        try {
            OffensiveScanner scanner = new OffensiveScanner();
            scanner.run(args);
        } catch (Exception e) {
            ConsoleUtils.printError("An error occurred: " + e.getMessage());
            if (isVerbose(args)) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }
    
    /**
     * Constructor - initializes the configuration manager
     */
    public OffensiveScanner() {
        this.configManager = new ConfigManager();
    }
    
    /**
     * Process command line arguments and run the scanner
     * 
     * @param args Command line arguments
     * @throws Exception if an error occurs
     */
    public void run(String[] args) throws Exception {
        try {
            CommandLine cmd = parseArguments(args);
            
            if (cmd.hasOption("h")) {
                printHelp();
                return;
            }
            
            if (cmd.hasOption("version")) {
                System.out.println(APP_NAME + " v" + VERSION);
                return;
            }
            
            // Check if config file is specified
            if (cmd.hasOption("c")) {
                String configFile = cmd.getOptionValue("c");
                configManager.loadConfig(configFile);
                ConsoleUtils.printInfo("Using configuration from " + configFile);
            } else {
                // Load default config
                configManager.loadDefaultConfig();
                ConsoleUtils.printInfo("Using default configuration");
            }
            
            // Enable verbose/debug output if specified
            if (cmd.hasOption("verbose")) {
                configManager.setConfigValue("general", "verbose", true);
            }
            
            if (cmd.hasOption("debug")) {
                configManager.setConfigValue("general", "debug", true);
            }
            
            // Check if target is specified
            if (!cmd.hasOption("t")) {
                ConsoleUtils.printError("No target specified. Use -t option to specify a target.");
                printHelp();
                return;
            }
            
            // Parse targets
            String targetSpec = cmd.getOptionValue("t");
            parseTargets(targetSpec);
            
            if (targets.isEmpty()) {
                ConsoleUtils.printError("No valid targets specified.");
                return;
            }
            
            ConsoleUtils.printBanner(APP_NAME, VERSION);
            
            // Determine which modules to enable based on command line options
            Set<ModuleType> enabledModules = determineEnabledModules(cmd);
            
            // Get report directory if specified
            String reportDir = cmd.hasOption("report-dir") ? 
                cmd.getOptionValue("report-dir") : "./reports";
            
            // Run scans for each target
            for (Target target : targets) {
                ConsoleUtils.printSectionHeader("Scanning Target: " + target.getOriginalTarget());
                
                // Initialize scan results
                ScanResults scanResults = new ScanResults();
                scanResults.setTarget(target);
                
                // Create and run scan manager
                ScanManager scanManager = new ScanManager(configManager, target, enabledModules, scanResults);
                scanManager.runScan();
                
                // Generate reports if requested
                if (cmd.hasOption("r")) {
                    scanManager.generateReports(reportDir);
                }
            }
            
            ConsoleUtils.printSuccess("All scans completed successfully.");
            
        } catch (ParseException e) {
            ConsoleUtils.printError("Error parsing command line arguments: " + e.getMessage());
            printHelp();
        } catch (Exception e) {
            ConsoleUtils.printError("Error during scan: " + e.getMessage());
            if (configManager.getConfigValue("general", "debug", false)) {
                e.printStackTrace();
            }
        }
    }
    
    /**
     * Determine which modules to enable based on command-line options
     * 
     * @param cmd The parsed command line
     * @return Set of enabled module types
     */
    private Set<ModuleType> determineEnabledModules(CommandLine cmd) {
        Set<ModuleType> enabledModules = new HashSet<>();
        
        // Full scan includes all modules except exploitation
        boolean fullScan = cmd.hasOption("f");
        
        // Add modules based on command-line flags
        if (cmd.hasOption("p") || fullScan) {
            enabledModules.add(ModuleType.PORT_SCANNING);
        }
        
        if (cmd.hasOption("s") || fullScan) {
            enabledModules.add(ModuleType.SERVICE_ENUMERATION);
        }
        
        if (cmd.hasOption("w") || fullScan) {
            enabledModules.add(ModuleType.WEB_SCANNING);
        }
        
        if (cmd.hasOption("v") || fullScan) {
            enabledModules.add(ModuleType.VULNERABILITY_SCANNING);
        }
        
        if (cmd.hasOption("d") || fullScan) {
            enabledModules.add(ModuleType.NETWORK_DISCOVERY);
        }
        
        if (cmd.hasOption("b") || fullScan) {
            enabledModules.add(ModuleType.BRUTE_FORCE);
        }
        
        if (cmd.hasOption("dns-enum") || fullScan) {
            enabledModules.add(ModuleType.DNS_ENUMERATION);
        }
        
        if (cmd.hasOption("ssl-analyze") || fullScan) {
            enabledModules.add(ModuleType.SSL_ANALYSIS);
        }
        
        if (cmd.hasOption("e")) {
            enabledModules.add(ModuleType.EXPLOITATION);
            ConsoleUtils.printWarning("CAUTION: Exploitation module enabled. Use only against systems you own or have permission to test.");
        }
        
        // If no modules were specified and not a full scan, default to port scanning
        if (enabledModules.isEmpty()) {
            enabledModules.add(ModuleType.PORT_SCANNING);
            ConsoleUtils.printWarning("No scan type specified. Running default port scan.");
        }
        
        return enabledModules;
    }
    
    /**
     * Parse command-line arguments
     * 
     * @param args Command line arguments
     * @return CommandLine object with parsed arguments
     * @throws ParseException if parsing fails
     */
    private CommandLine parseArguments(String[] args) throws ParseException {
        Options options = new Options();
        
        // Target options
        options.addOption("t", "target", true, "Target to scan (IP, hostname, or IP range)");
        
        // Scan type options
        options.addOption("p", "port-scan", false, "Perform port scanning");
        options.addOption("s", "service-enum", false, "Perform service enumeration");
        options.addOption("w", "web-scan", false, "Perform web application scanning");
        options.addOption("v", "vuln-scan", false, "Perform vulnerability scanning");
        options.addOption("d", "discover", false, "Perform network discovery");
        options.addOption("b", "brute-force", false, "Perform brute force attacks");
        options.addOption(null, "dns-enum", false, "Perform DNS enumeration");
        options.addOption(null, "ssl-analyze", false, "Perform SSL/TLS analysis");
        options.addOption("f", "full-scan", false, "Perform full scan (all modules except exploitation)");
        options.addOption("e", "exploit", false, "Enable exploitation modules (use with caution)");
        
        // Output options
        options.addOption("r", "report", false, "Generate reports");
        options.addOption(null, "report-dir", true, "Directory to store reports");
        
        // Configuration options
        options.addOption("c", "config", true, "Path to configuration file");
        options.addOption(null, "verbose", false, "Enable verbose output");
        options.addOption(null, "debug", false, "Enable debug output");
        
        // Help and version options
        options.addOption("h", "help", false, "Display help message");
        options.addOption(null, "version", false, "Display version information");
        
        CommandLineParser parser = new DefaultParser();
        return parser.parse(options, args);
    }
    
    /**
     * Print help information
     */
    private void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(100);
        
        Options options = new Options();
        options.addOption("t", "target", true, "Target to scan (IP, hostname, or IP range)");
        options.addOption("p", "port-scan", false, "Perform port scanning");
        options.addOption("s", "service-enum", false, "Perform service enumeration");
        options.addOption("w", "web-scan", false, "Perform web application scanning");
        options.addOption("v", "vuln-scan", false, "Perform vulnerability scanning");
        options.addOption("d", "discover", false, "Perform network discovery");
        options.addOption("b", "brute-force", false, "Perform brute force attacks");
        options.addOption(null, "dns-enum", false, "Perform DNS enumeration");
        options.addOption(null, "ssl-analyze", false, "Perform SSL/TLS analysis");
        options.addOption("f", "full-scan", false, "Perform full scan (all modules except exploitation)");
        options.addOption("e", "exploit", false, "Enable exploitation modules (use with caution)");
        options.addOption("r", "report", false, "Generate reports");
        options.addOption(null, "report-dir", true, "Directory to store reports");
        options.addOption("c", "config", true, "Path to configuration file");
        options.addOption(null, "verbose", false, "Enable verbose output");
        options.addOption(null, "debug", false, "Enable debug output");
        options.addOption("h", "help", false, "Display help message");
        options.addOption(null, "version", false, "Display version information");
        
        formatter.printHelp("java -jar offensive-scanner.jar", 
                            "\n" + APP_NAME + " v" + VERSION + " - A comprehensive security scanning tool\n\n",
                            options, 
                            "\nExamples:\n" +
                            "  java -jar offensive-scanner.jar -t 192.168.1.1 -p\n" +
                            "  java -jar offensive-scanner.jar -t example.com -f -r\n" +
                            "  java -jar offensive-scanner.jar -t 192.168.1.0/24 -d -s\n", 
                            true);
    }
    
    /**
     * Parse target specification into Target objects
     * 
     * @param targetSpec The target specification string
     */
    private void parseTargets(String targetSpec) {
        if (targetSpec == null || targetSpec.isEmpty()) {
            return;
        }
        
        // Split by comma for multiple targets
        String[] targetStrings = targetSpec.split(",");
        
        for (String targetStr : targetStrings) {
            try {
                Target target = Target.parse(targetStr.trim());
                targets.add(target);
                ConsoleUtils.printVerbose("Added target: " + target.toString());
            } catch (Exception e) {
                ConsoleUtils.printError("Invalid target: " + targetStr + " - " + e.getMessage());
            }
        }
    }
    
    /**
     * Check if verbose mode is enabled in arguments
     * 
     * @param args Command line arguments
     * @return true if verbose mode is enabled
     */
    private static boolean isVerbose(String[] args) {
        for (String arg : args) {
            if (arg.equals("--verbose")) {
                return true;
            }
        }
        return false;
    }
} 