package com.offensivescanner.reporting;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.core.VulnerabilitySeverity;
import com.offensivescanner.utils.ConsoleUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Generates reports in various formats (text, HTML, JSON) for scan results.
 */
public class ReportGenerator {
    
    private final ConfigManager configManager;
    private final ScanResults scanResults;
    
    /**
     * Create a new report generator
     * 
     * @param configManager The configuration manager
     * @param scanResults The scan results to report on
     */
    public ReportGenerator(ConfigManager configManager, ScanResults scanResults) {
        this.configManager = configManager;
        this.scanResults = scanResults;
    }
    
    /**
     * Generate reports in all configured formats
     * 
     * @param reportDir The directory to store reports
     * @throws IOException if there's an error writing the reports
     */
    public void generateReports(String reportDir) throws IOException {
        // Create the report directory if it doesn't exist
        File reportDirectory = new File(reportDir);
        if (!reportDirectory.exists()) {
            if (reportDirectory.mkdirs()) {
                ConsoleUtils.printInfo("Created report directory: " + reportDir);
            } else {
                throw new IOException("Failed to create report directory: " + reportDir);
            }
        }
        
        // Generate timestamp for the report filename
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd-HHmmss");
        String timestamp = dateFormat.format(new Date());
        
        // Get target info
        Target target = scanResults.getTarget();
        String targetName = "unknown";
        if (target != null) {
            targetName = target.getOriginalTarget().replaceAll("[:/\\\\?*|<>\"]", "_");
        }
        
        // Generate text report (always)
        generateTextReport(reportDir, targetName, timestamp);
        
        // Check if other report formats are configured
        List<String> formats = configManager.getConfigValue("reporting", "formats", List.of("text"));
        
        // Generate reports in other formats if configured
        for (String format : formats) {
            if ("html".equalsIgnoreCase(format)) {
                generateHtmlReport(reportDir, targetName, timestamp);
            } else if ("json".equalsIgnoreCase(format)) {
                generateJsonReport(reportDir, targetName, timestamp);
            }
            // Add other formats as needed
        }
    }
    
    /**
     * Generate a simple text report
     * 
     * @param reportDir The directory to store the report
     * @param targetName The target name for the filename
     * @param timestamp The timestamp for the filename
     * @throws IOException if there's an error writing the report
     */
    private void generateTextReport(String reportDir, String targetName, String timestamp) throws IOException {
        String filename = reportDir + File.separator + "report_" + targetName + "_" + timestamp + ".txt";
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("OFFENSIVE SCANNER REPORT");
            writer.println("========================");
            writer.println("Scan time: " + new Date());
            writer.println();
            
            // Target information
            if (scanResults.getTarget() != null) {
                writer.println("Target: " + scanResults.getTarget().getOriginalTarget());
            }
            
            // Scan time
            writer.println("Scan started: " + new Date(scanResults.getScanStartTime()));
            writer.println("Scan ended: " + new Date(scanResults.getScanEndTime()));
            writer.println("Duration: " + formatDuration(scanResults.getScanDuration()));
            writer.println();
            
            // Summary statistics
            writer.println("SUMMARY");
            writer.println("-------");
            writer.println("Hosts scanned: " + scanResults.getDiscoveredHosts().size());
            writer.println("Open ports found: " + scanResults.getOpenPortCount());
            
            // Vulnerability counts by severity
            writer.println("Vulnerabilities:");
            writer.println("  Critical: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.CRITICAL));
            writer.println("  High: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.HIGH));
            writer.println("  Medium: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.MEDIUM));
            writer.println("  Low: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.LOW));
            writer.println("  Info: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.INFO));
            writer.println("Web vulnerabilities: " + scanResults.getWebVulnerabilityCount());
            writer.println();
            
            // Detailed report
            writer.println("DETAILED RESULTS");
            writer.println("---------------");
            writer.println(scanResults.getSummary());
        }
        
        ConsoleUtils.printSuccess("Text report generated: " + filename);
    }
    
    /**
     * Generate an HTML report
     * 
     * @param reportDir The directory to store the report
     * @param targetName The target name for the filename
     * @param timestamp The timestamp for the filename
     * @throws IOException if there's an error writing the report
     */
    private void generateHtmlReport(String reportDir, String targetName, String timestamp) throws IOException {
        String filename = reportDir + File.separator + "report_" + targetName + "_" + timestamp + ".html";
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html>");
            writer.println("<head>");
            writer.println("<title>Offensive Scanner Report</title>");
            writer.println("<style>");
            writer.println("body { font-family: Arial, sans-serif; margin: 20px; }");
            writer.println("h1 { color: #2c3e50; }");
            writer.println("h2 { color: #3498db; }");
            writer.println(".severity-critical { color: #e74c3c; }");
            writer.println(".severity-high { color: #e67e22; }");
            writer.println(".severity-medium { color: #f39c12; }");
            writer.println(".severity-low { color: #27ae60; }");
            writer.println(".severity-info { color: #3498db; }");
            writer.println("</style>");
            writer.println("</head>");
            writer.println("<body>");
            writer.println("<h1>Offensive Scanner Report</h1>");
            writer.println("<p>Generated: " + new Date() + "</p>");
            
            // Add report content here
            writer.println("<h2>Target Information</h2>");
            if (scanResults.getTarget() != null) {
                writer.println("<p>Target: " + scanResults.getTarget().getOriginalTarget() + "</p>");
            }
            
            writer.println("<h2>Scan Summary</h2>");
            writer.println("<ul>");
            writer.println("<li>Scan started: " + new Date(scanResults.getScanStartTime()) + "</li>");
            writer.println("<li>Scan ended: " + new Date(scanResults.getScanEndTime()) + "</li>");
            writer.println("<li>Duration: " + formatDuration(scanResults.getScanDuration()) + "</li>");
            writer.println("<li>Hosts scanned: " + scanResults.getDiscoveredHosts().size() + "</li>");
            writer.println("<li>Open ports found: " + scanResults.getOpenPortCount() + "</li>");
            writer.println("</ul>");
            
            writer.println("<h2>Vulnerabilities</h2>");
            writer.println("<ul>");
            writer.println("<li class='severity-critical'>Critical: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.CRITICAL) + "</li>");
            writer.println("<li class='severity-high'>High: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.HIGH) + "</li>");
            writer.println("<li class='severity-medium'>Medium: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.MEDIUM) + "</li>");
            writer.println("<li class='severity-low'>Low: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.LOW) + "</li>");
            writer.println("<li class='severity-info'>Info: " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.INFO) + "</li>");
            writer.println("<li>Web vulnerabilities: " + scanResults.getWebVulnerabilityCount() + "</li>");
            writer.println("</ul>");
            
            // Add more detailed report sections here
            
            writer.println("</body>");
            writer.println("</html>");
        }
        
        ConsoleUtils.printSuccess("HTML report generated: " + filename);
    }
    
    /**
     * Generate a JSON report
     * 
     * @param reportDir The directory to store the report
     * @param targetName The target name for the filename
     * @param timestamp The timestamp for the filename
     * @throws IOException if there's an error writing the report
     */
    private void generateJsonReport(String reportDir, String targetName, String timestamp) throws IOException {
        String filename = reportDir + File.separator + "report_" + targetName + "_" + timestamp + ".json";
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("{");
            writer.println("  \"report\": {");
            writer.println("    \"timestamp\": \"" + new Date() + "\",");
            writer.println("    \"target\": \"" + (scanResults.getTarget() != null ? scanResults.getTarget().getOriginalTarget() : "unknown") + "\",");
            writer.println("    \"scanDuration\": \"" + formatDuration(scanResults.getScanDuration()) + "\",");
            writer.println("    \"summary\": {");
            writer.println("      \"hostsScanned\": " + scanResults.getDiscoveredHosts().size() + ",");
            writer.println("      \"openPorts\": " + scanResults.getOpenPortCount() + ",");
            writer.println("      \"vulnerabilities\": {");
            writer.println("        \"critical\": " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.CRITICAL) + ",");
            writer.println("        \"high\": " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.HIGH) + ",");
            writer.println("        \"medium\": " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.MEDIUM) + ",");
            writer.println("        \"low\": " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.LOW) + ",");
            writer.println("        \"info\": " + scanResults.getVulnerabilityCount(VulnerabilitySeverity.INFO) + ",");
            writer.println("        \"web\": " + scanResults.getWebVulnerabilityCount());
            writer.println("      }");
            writer.println("    }");
            writer.println("  }");
            writer.println("}");
        }
        
        ConsoleUtils.printSuccess("JSON report generated: " + filename);
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
} 