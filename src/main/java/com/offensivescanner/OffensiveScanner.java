package com.offensivescanner;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.modules.ModuleType;
import com.offensivescanner.utils.ConsoleUtils;

import org.apache.commons.cli.*;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

/**
 * Main class for the Offensive Scanner application.
 * Handles command-line parsing and initiates scanning.
 */
public class OffensiveScanner {

    private static final String APP_NAME = "Offensive Scanner";
    private static final String VERSION = "1.0.0";

    /**
     * Entry point for the application
     *
     * @param args Command-line arguments
     */
    public static void main(String[] args) {
        try {
            // Parse command-line arguments
            CommandLine cmd = parseArguments(args);

            // Show help if requested
            if (cmd.hasOption("h")) {
                printHelp();
                return;
            }

            // Show version if requested
            if (cmd.hasOption("version")) {
                System.out.println(APP_NAME + " version " + VERSION);
                return;
            }

            // Print the banner
            ConsoleUtils.printBanner(APP_NAME, VERSION);

            // Check if a target is specified
            if (!cmd.hasOption("t")) {
                System.err.println("Error: Target is required.");
                printHelp();
                System.exit(1);
            }

            // Load configuration
            ConfigManager configManager = new ConfigManager();
            try {
                configManager.loadDefaultConfig();
            } catch (Exception e) {
                ConsoleUtils.printWarning("Failed to load configuration file: " + e.getMessage());
                ConsoleUtils.printInfo("Using default configuration values");
            }

            // Determine which modules to run
            Set<ModuleType> enabledModules = determineEnabledModules(cmd);

            if (enabledModules.isEmpty()) {
                ConsoleUtils.printWarning("No scan modules specified. Use --help to see available options.");
                System.exit(1);
            }

            // Enable verbose/debug modes if requested
            if (cmd.hasOption("verbose")) {
                configManager.setConfigValue("general", "verbose", true);
            }

            if (cmd.hasOption("debug")) {
                configManager.setConfigValue("general", "debug", true);
            }

            // Parse target
            String targetStr = cmd.getOptionValue("t");
            Target target = Target.parse(targetStr);

            // Initialize scan results
            ScanResults scanResults = new ScanResults();
            scanResults.setTarget(target);

            // Initialize scan manager
            ScanManager scanManager = new ScanManager(configManager, target, enabledModules, scanResults);

            // Run the scan
            ConsoleUtils.printInfo("Starting scan against target: " + targetStr);
            scanManager.runScan();

            // Generate reports if requested
            if (cmd.hasOption("r")) {
                String reportDir = cmd.getOptionValue("report-dir", "./reports");
                File reportDirFile = new File(reportDir);
                if (!reportDirFile.exists()) {
                    reportDirFile.mkdirs();
                }
                scanManager.generateReports(reportDir);
            }

            ConsoleUtils.printSuccess("Scan completed successfully.");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Parse command-line arguments using Apache Commons CLI
     *
     * @param args The command-line arguments
     * @return The parsed command line
     * @throws ParseException if the arguments cannot be parsed
     */
    private static CommandLine parseArguments(String[] args) throws ParseException {
        Options options = createOptions();
        CommandLineParser parser = new DefaultParser();
        return parser.parse(options, args);
    }

    /**
     * Create the command-line options
     *
     * @return The options
     */
    private static Options createOptions() {
        Options options = new Options();

        // Target option (required)
        Option targetOption = Option.builder("t")
                .longOpt("target")
                .desc("Target to scan (IP, hostname, or IP range)")
                .hasArg()
                .argName("TARGET")
                .build();
        options.addOption(targetOption);

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

        // Report options
        options.addOption("r", "report", false, "Generate reports");
        Option reportDirOption = Option.builder()
                .longOpt("report-dir")
                .desc("Directory to store reports")
                .hasArg()
                .argName("DIR")
                .build();
        options.addOption(reportDirOption);

        // Config option
        Option configOption = Option.builder("c")
                .longOpt("config")
                .desc("Path to configuration file")
                .hasArg()
                .argName("FILE")
                .build();
        options.addOption(configOption);

        // Output options
        options.addOption(null, "verbose", false, "Enable verbose output");
        options.addOption(null, "debug", false, "Enable debug output");

        // Help and version options
        options.addOption("h", "help", false, "Display help message");
        options.addOption(null, "version", false, "Display version information");

        return options;
    }

    /**
     * Determine which modules to enable based on command-line arguments
     *
     * @param cmd The parsed command line
     * @return The set of enabled module types
     */
    private static Set<ModuleType> determineEnabledModules(CommandLine cmd) {
        Set<ModuleType> enabledModules = new HashSet<>();

        // Individual modules
        if (cmd.hasOption("p")) {
            enabledModules.add(ModuleType.PORT_SCANNING);
        }
        if (cmd.hasOption("s")) {
            enabledModules.add(ModuleType.SERVICE_ENUMERATION);
        }
        if (cmd.hasOption("w")) {
            enabledModules.add(ModuleType.WEB_SCANNING);
        }
        if (cmd.hasOption("v")) {
            enabledModules.add(ModuleType.VULNERABILITY_SCANNING);
        }
        if (cmd.hasOption("d")) {
            enabledModules.add(ModuleType.NETWORK_DISCOVERY);
        }
        if (cmd.hasOption("b")) {
            enabledModules.add(ModuleType.BRUTE_FORCE);
        }
        if (cmd.hasOption("dns-enum")) {
            enabledModules.add(ModuleType.DNS_ENUMERATION);
        }
        if (cmd.hasOption("ssl-analyze")) {
            enabledModules.add(ModuleType.SSL_ANALYSIS);
        }
        if (cmd.hasOption("e")) {
            enabledModules.add(ModuleType.EXPLOITATION);
        }

        // Full scan
        if (cmd.hasOption("f")) {
            enabledModules.add(ModuleType.PORT_SCANNING);
            enabledModules.add(ModuleType.SERVICE_ENUMERATION);
            enabledModules.add(ModuleType.WEB_SCANNING);
            enabledModules.add(ModuleType.VULNERABILITY_SCANNING);
            enabledModules.add(ModuleType.NETWORK_DISCOVERY);
            enabledModules.add(ModuleType.BRUTE_FORCE);
            enabledModules.add(ModuleType.DNS_ENUMERATION);
            enabledModules.add(ModuleType.SSL_ANALYSIS);
        }

        return enabledModules;
    }

    /**
     * Print help information
     */
    private static void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar offensive-scanner.jar [options]", createOptions());
    }

    /**
     * Generate a report of the scan results
     *
     * @param reportDir The directory to store the report
     */
    private static void generateReport(String reportDir) {
        try {
            File dir = new File(reportDir);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            String filename = reportDir + File.separator + "scan_report_" +
                    new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date()) + ".txt";

            try (java.io.PrintWriter writer = new java.io.PrintWriter(new java.io.FileWriter(filename))) {
                writer.println("=== Offensive Scanner Report ===");
                writer.println("Generated: " + new java.util.Date());
                writer.println("----------------");
                writer.println("Scan Summary:");
                // Here would be the actual reporting content based on scan results
                writer.println("Report details would be included here");
            }

            ConsoleUtils.printSuccess("Report generated: " + filename);
        } catch (Exception e) {
            ConsoleUtils.printError("Error generating report: " + e.getMessage());
        }
    }
} 