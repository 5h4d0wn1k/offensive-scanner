package com.offensivescanner.modules.service;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.modules.AbstractScanModule;
import com.offensivescanner.modules.ModuleType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

/**
 * Scanner module for enumerating service information on open ports.
 * Attempts to connect to open ports and gather version information.
 */
public class ServiceEnumerator extends AbstractScanModule {
    
    private final int timeout;
    private final int threads;
    
    // Common service fingerprints and their probe strings
    private static final Map<Integer, ServiceProbe> SERVICE_PROBES = new HashMap<>();
    
    static {
        // HTTP/HTTPS
        SERVICE_PROBES.put(80, new ServiceProbe("HTTP", "HEAD / HTTP/1.0\r\n\r\n", "Server: (.+)\r\n"));
        SERVICE_PROBES.put(443, new ServiceProbe("HTTPS", "HEAD / HTTP/1.0\r\n\r\n", "Server: (.+)\r\n"));
        SERVICE_PROBES.put(8080, new ServiceProbe("HTTP", "HEAD / HTTP/1.0\r\n\r\n", "Server: (.+)\r\n"));
        
        // FTP
        SERVICE_PROBES.put(21, new ServiceProbe("FTP", "", "^220 (.+)\r\n"));
        
        // SSH
        SERVICE_PROBES.put(22, new ServiceProbe("SSH", "", "^SSH-\\d\\.\\d+-(.+)\r\n"));
        
        // SMTP
        SERVICE_PROBES.put(25, new ServiceProbe("SMTP", "HELO scan.test\r\n", "^220 (.+)\r\n"));
        SERVICE_PROBES.put(587, new ServiceProbe("SMTP", "HELO scan.test\r\n", "^220 (.+)\r\n"));
        
        // DNS
        SERVICE_PROBES.put(53, new ServiceProbe("DNS", "", ""));  // DNS requires special handling
        
        // POP3
        SERVICE_PROBES.put(110, new ServiceProbe("POP3", "", "^\\+OK (.+)\r\n"));
        SERVICE_PROBES.put(995, new ServiceProbe("POP3S", "", "^\\+OK (.+)\r\n"));
        
        // IMAP
        SERVICE_PROBES.put(143, new ServiceProbe("IMAP", "", "^\\* OK (.+)\r\n"));
        SERVICE_PROBES.put(993, new ServiceProbe("IMAPS", "", "^\\* OK (.+)\r\n"));
        
        // RDP
        SERVICE_PROBES.put(3389, new ServiceProbe("RDP", "", ""));  // RDP requires special handling
        
        // MySQL
        SERVICE_PROBES.put(3306, new ServiceProbe("MySQL", "", ""));  // MySQL requires special handling
        
        // SMB
        SERVICE_PROBES.put(445, new ServiceProbe("SMB", "", ""));  // SMB requires special handling
    }
    
    /**
     * Create a new service enumerator module
     * 
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     */
    public ServiceEnumerator(ConfigManager configManager, ScanResults scanResults) {
        super(configManager, scanResults, "Service Enumerator", 
              "Enumerates service information on open ports", ModuleType.SERVICE_ENUMERATION);
        
        this.timeout = configManager.getConfigValue("service_enum", "timeout", 10);
        this.threads = configManager.getConfigValue("general", "threads", 10);
    }
    
    @Override
    public void scan(Target target) throws Exception {
        logInfo("Starting service enumeration against " + target.toString());
        
        // Use scan results to get open ports
        Map<InetAddress, Map<Integer, ScanResults.PortInfo>> openPorts = scanResults.getOpenPorts();
        
        if (openPorts.isEmpty()) {
            logWarning("No open ports found to enumerate. Run port scan first.");
            return;
        }
        
        logInfo("Enumerating services on " + countOpenPorts(openPorts) + " open ports");
        
        long startTime = System.currentTimeMillis();
        
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<ServiceResult>> futures = new ArrayList<>();
        
        // For each host with open ports
        for (Map.Entry<InetAddress, Map<Integer, ScanResults.PortInfo>> hostEntry : openPorts.entrySet()) {
            InetAddress host = hostEntry.getKey();
            Map<Integer, ScanResults.PortInfo> hostPorts = hostEntry.getValue();
            
            // For each open port
            for (Integer port : hostPorts.keySet()) {
                Callable<ServiceResult> scanner = () -> detectService(host, port);
                futures.add(executor.submit(scanner));
            }
        }
        
        // Process results
        int detectedServices = 0;
        for (Future<ServiceResult> future : futures) {
            try {
                ServiceResult result = future.get();
                if (result.serviceName != null && !result.serviceName.isEmpty()) {
                    detectedServices++;
                    
                    // Update in global scan results
                    scanResults.addOpenPort(result.host, result.port, "tcp", 
                                           result.serviceName, result.serviceVersion);
                    
                    logSuccess("Detected service: " + result.host.getHostAddress() + ":" + 
                              result.port + " - " + result.serviceName + 
                              (result.serviceVersion.isEmpty() ? "" : " " + result.serviceVersion));
                }
            } catch (Exception e) {
                logDebug("Error processing service detection result: " + e.getMessage());
            }
        }
        
        executor.shutdown();
        
        long duration = System.currentTimeMillis() - startTime;
        logInfo("Service enumeration completed in " + (duration / 1000.0) + " seconds");
        logSuccess("Detected " + detectedServices + " services");
    }
    
    /**
     * Count the total number of open ports across all hosts
     * 
     * @param openPorts Map of hosts to open ports
     * @return Total count of open ports
     */
    private int countOpenPorts(Map<InetAddress, Map<Integer, ScanResults.PortInfo>> openPorts) {
        int count = 0;
        for (Map<Integer, ScanResults.PortInfo> hostPorts : openPorts.values()) {
            count += hostPorts.size();
        }
        return count;
    }
    
    /**
     * Detect the service running on a specific port
     * 
     * @param host The host to connect to
     * @param port The port to connect to
     * @return The service detection result
     */
    private ServiceResult detectService(InetAddress host, int port) {
        ServiceResult result = new ServiceResult(host, port);
        
        // Check if we have a probe for this port
        ServiceProbe probe = SERVICE_PROBES.getOrDefault(port, new ServiceProbe("Unknown", "", ""));
        
        // Set default service name based on common ports
        result.serviceName = probe.serviceName;
        
        // Try to connect and get a banner
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeout * 1000);
            socket.setSoTimeout(timeout * 1000);
            
            // If we have a probe string, send it
            if (!probe.probeString.isEmpty()) {
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.print(probe.probeString);
                out.flush();
            }
            
            // Read response
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            int lineCount = 0;
            
            while ((line = in.readLine()) != null && lineCount < 5) {
                response.append(line).append("\r\n");
                lineCount++;
            }
            
            // Try to extract version information
            if (!probe.versionRegex.isEmpty()) {
                result.serviceVersion = extractVersion(response.toString(), probe.versionRegex);
            }
            
            // If we still don't have a version, use part of the banner
            if (result.serviceVersion.isEmpty() && response.length() > 0) {
                String banner = response.toString().trim();
                if (banner.length() > 50) {
                    banner = banner.substring(0, 50) + "...";
                }
                result.serviceVersion = banner;
            }
            
        } catch (IOException e) {
            logDebug("Error connecting to " + host.getHostAddress() + ":" + port + ": " + e.getMessage());
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
        
        return result;
    }
    
    /**
     * Extract version information from a service banner
     * 
     * @param banner The service banner
     * @param regex The regular expression to extract version
     * @return The extracted version or an empty string
     */
    private String extractVersion(String banner, String regex) {
        if (banner == null || banner.isEmpty() || regex.isEmpty()) {
            return "";
        }
        
        try {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
            java.util.regex.Matcher matcher = pattern.matcher(banner);
            
            if (matcher.find() && matcher.groupCount() >= 1) {
                return matcher.group(1).trim();
            }
        } catch (Exception e) {
            logDebug("Error extracting version with regex: " + e.getMessage());
        }
        
        return "";
    }
    
    /**
     * Class to hold service probe information
     */
    private static class ServiceProbe {
        private final String serviceName;
        private final String probeString;
        private final String versionRegex;
        
        public ServiceProbe(String serviceName, String probeString, String versionRegex) {
            this.serviceName = serviceName;
            this.probeString = probeString;
            this.versionRegex = versionRegex;
        }
    }
    
    /**
     * Class to hold the result of a service detection
     */
    private static class ServiceResult {
        private final InetAddress host;
        private final int port;
        private String serviceName = "";
        private String serviceVersion = "";
        
        public ServiceResult(InetAddress host, int port) {
            this.host = host;
            this.port = port;
        }
    }
} 