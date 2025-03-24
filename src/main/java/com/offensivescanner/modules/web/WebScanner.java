package com.offensivescanner.modules.web;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.core.VulnerabilitySeverity;
import com.offensivescanner.modules.AbstractScanModule;
import com.offensivescanner.modules.ModuleType;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * WebScanner module for detecting web vulnerabilities and misconfigurations.
 */
public class WebScanner extends AbstractScanModule {
    
    private final int timeout;
    private final int maxDepth;
    private final int threads;
    
    /**
     * Create a new web scanner module
     * 
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     */
    public WebScanner(ConfigManager configManager, ScanResults scanResults) {
        super(configManager, scanResults, "Web Scanner", 
              "Scans for web vulnerabilities and misconfigurations", ModuleType.WEB_SCANNING);
        
        this.timeout = configManager.getConfigValue("web_scan", "timeout", 15);
        this.maxDepth = configManager.getConfigValue("web_scan", "max_depth", 3);
        this.threads = configManager.getConfigValue("web_scan", "threads", 5);
    }
    
    @Override
    public void scan(Target target) throws Exception {
        logInfo("Starting web scan against " + target.toString());
        logInfo("Web scan timeout configured for " + timeout + " seconds");
        logInfo("Maximum crawl depth set to " + maxDepth + " levels");
        logInfo("Using " + threads + " concurrent threads for scanning");
        
        // Get open ports from previous scans
        Map<InetAddress, Map<Integer, ScanResults.PortInfo>> openPorts = scanResults.getOpenPorts();
        
        if (openPorts.isEmpty()) {
            logWarning("No open ports found for web scanning. Run port scan first.");
            return;
        }
        
        // List of potential web ports to check
        List<Integer> webPorts = new ArrayList<>();
        webPorts.add(80);
        webPorts.add(443);
        webPorts.add(8080);
        webPorts.add(8443);
        
        // Get host addresses
        List<InetAddress> hosts = target.getResolvedAddresses();
        int webServersFound = 0;
        
        // For each target host
        for (InetAddress host : hosts) {
            // Check if this host has open ports
            if (!openPorts.containsKey(host)) {
                continue;
            }
            
            Map<Integer, ScanResults.PortInfo> hostPorts = openPorts.get(host);
            
            // Check for web ports
            for (Integer port : hostPorts.keySet()) {
                if (webPorts.contains(port) || isWebPort(hostPorts.get(port))) {
                    webServersFound++;
                    logSuccess("Found web server at " + host.getHostAddress() + ":" + port);
                    
                    // Simulated web scan - in a real implementation, this would scan for vulnerabilities
                    simulateWebScan(host, port);
                }
            }
        }
        
        if (webServersFound == 0) {
            logInfo("No web servers detected on the target hosts.");
        } else {
            logInfo("Web scan completed on " + webServersFound + " web server(s).");
        }
    }
    
    /**
     * Check if a port is likely to be running a web server
     * 
     * @param portInfo The port information
     * @return true if the port is likely running a web server
     */
    private boolean isWebPort(ScanResults.PortInfo portInfo) {
        String service = portInfo.getService().toLowerCase();
        return service.contains("http") || service.contains("web") || service.contains("ssl");
    }
    
    /**
     * Simulate a web scan (placeholder for actual implementation)
     * This would be replaced with real scanning logic in a production version
     * 
     * @param host The host to scan
     * @param port The port to scan
     */
    private void simulateWebScan(InetAddress host, int port) {
        String protocol = port == 443 || port == 8443 ? "https" : "http";
        String url = protocol + "://" + host.getHostAddress() + ":" + port;
        
        logInfo("Scanning " + url + " for vulnerabilities...");
        
        // Simulate finding some issues (for demonstration)
        if (Math.random() < 0.3) {
            // Add a simulated XSS vulnerability
            ScanResults.WebVulnerability xss = new ScanResults.WebVulnerability(
                "Cross-Site Scripting (XSS)",
                "Reflected XSS vulnerability detected in search parameter",
                VulnerabilitySeverity.HIGH,
                url + "/search?q=test",
                "q",
                "<script>alert(1)</script>",
                "Implement proper input validation and output encoding"
            );
            scanResults.addWebVulnerability(xss);
            logWarning("Found XSS vulnerability at " + url + "/search");
        }
        
        if (Math.random() < 0.2) {
            // Add a simulated SQL injection vulnerability
            ScanResults.WebVulnerability sqli = new ScanResults.WebVulnerability(
                "SQL Injection",
                "SQL injection vulnerability detected in id parameter",
                VulnerabilitySeverity.CRITICAL,
                url + "/product?id=1",
                "id",
                "1' OR 1=1 --",
                "Use prepared statements and parameterized queries"
            );
            scanResults.addWebVulnerability(sqli);
            logError("Found SQL Injection vulnerability at " + url + "/product");
        }
        
        // This would include actual scanning for vulnerabilities like XSS, SQLi, CSRF, etc.
    }
} 