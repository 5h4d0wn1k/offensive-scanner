package com.offensivescanner.modules.port;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.modules.AbstractScanModule;
import com.offensivescanner.modules.ModuleType;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;

/**
 * Scanner module for detecting open ports on target hosts.
 * Supports TCP connect scan by default.
 */
public class PortScanner extends AbstractScanModule {
    
    private final Map<InetAddress, Map<Integer, String>> openPorts = new HashMap<>();
    private final int timeout;
    private final int threads;
    private final List<Integer> ports;
    private final String scanType;
    
    /**
     * Create a new port scanner module
     * 
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     */
    public PortScanner(ConfigManager configManager, ScanResults scanResults) {
        super(configManager, scanResults, "Port Scanner", 
              "Scans for open ports on target hosts", ModuleType.PORT_SCANNING);
        
        this.timeout = configManager.getConfigValue("port_scan", "timeout", 5);
        this.threads = configManager.getConfigValue("port_scan", "threads", 50);
        this.scanType = configManager.getConfigValue("port_scan", "scan_type", "CONNECT").toUpperCase();
        
        // Parse the default ports from configuration
        this.ports = parsePortsString(
            configManager.getConfigValue("port_scan", "default_ports", 
                "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080")
        );
    }
    
    @Override
    public void scan(Target target) throws Exception {
        logInfo("Starting port scan against " + target.toString() + " with " + threads + " threads");
        logVerbose("Scanning " + ports.size() + " ports in " + scanType + " mode");
        
        long startTime = System.currentTimeMillis();
        
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<PortResult>> futures = new ArrayList<>();
        
        // For each target host
        for (InetAddress host : target.getResolvedAddresses()) {
            openPorts.put(host, new HashMap<>());
            
            // For each port to scan
            for (int port : ports) {
                Callable<PortResult> scanner = () -> scanPort(host, port);
                futures.add(executor.submit(scanner));
            }
        }
        
        // Process results
        int openPortCount = 0;
        for (Future<PortResult> future : futures) {
            try {
                PortResult result = future.get();
                if (result.isOpen) {
                    openPortCount++;
                    
                    // Add to local results
                    openPorts.get(result.host).put(result.port, "tcp");
                    
                    // Add to global scan results
                    scanResults.addOpenPort(result.host, result.port, "tcp", "", "");
                    
                    logSuccess("Found open port: " + result.host.getHostAddress() + ":" + result.port);
                }
            } catch (Exception e) {
                logDebug("Error processing scan result: " + e.getMessage());
            }
        }
        
        executor.shutdown();
        
        long duration = System.currentTimeMillis() - startTime;
        logInfo("Port scan completed in " + (duration / 1000.0) + " seconds");
        logSuccess("Found " + openPortCount + " open ports");
    }
    
    /**
     * Scan a single port on a host
     * 
     * @param host The host to scan
     * @param port The port to scan
     * @return The port scan result
     */
    private PortResult scanPort(InetAddress host, int port) {
        PortResult result = new PortResult(host, port, false);
        
        switch (scanType) {
            case "CONNECT":
                result.isOpen = performConnectScan(host, port);
                break;
            case "SYN":
                // SYN scan requires raw sockets, which requires special permissions
                // Fallback to connect scan for now
                logDebug("SYN scan is not fully implemented, falling back to CONNECT scan for " + 
                        host.getHostAddress() + ":" + port);
                result.isOpen = performConnectScan(host, port);
                break;
            case "UDP":
                // UDP scan is not implemented yet
                logDebug("UDP scan is not implemented yet, skipping " + 
                        host.getHostAddress() + ":" + port);
                break;
            default:
                logWarning("Unknown scan type: " + scanType + ", falling back to CONNECT scan");
                result.isOpen = performConnectScan(host, port);
                break;
        }
        
        return result;
    }
    
    /**
     * Perform a TCP connect scan on a host/port
     * 
     * @param host The host to scan
     * @param port The port to scan
     * @return true if the port is open
     */
    private boolean performConnectScan(InetAddress host, int port) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeout * 1000);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }
    
    /**
     * Parse a comma-separated string of ports into a list of integers
     * 
     * @param portsString The string of ports (e.g., "80,443,8080")
     * @return A list of port numbers
     */
    private List<Integer> parsePortsString(String portsString) {
        List<Integer> portList = new ArrayList<>();
        
        if (portsString == null || portsString.isEmpty()) {
            return portList;
        }
        
        for (String portStr : portsString.split(",")) {
            try {
                if (portStr.contains("-")) {
                    // Port range (e.g., "1000-2000")
                    String[] range = portStr.split("-");
                    int start = Integer.parseInt(range[0].trim());
                    int end = Integer.parseInt(range[1].trim());
                    
                    for (int i = start; i <= end; i++) {
                        if (i > 0 && i < 65536) {
                            portList.add(i);
                        }
                    }
                } else {
                    // Single port
                    int port = Integer.parseInt(portStr.trim());
                    if (port > 0 && port < 65536) {
                        portList.add(port);
                    }
                }
            } catch (NumberFormatException e) {
                logWarning("Invalid port: " + portStr);
            }
        }
        
        return portList;
    }
    
    /**
     * Get the map of open ports for all hosts
     * 
     * @return Map of hosts to open ports
     */
    public Map<InetAddress, Map<Integer, String>> getOpenPorts() {
        return openPorts;
    }
    
    /**
     * Class to hold the result of a port scan
     */
    private static class PortResult {
        private final InetAddress host;
        private final int port;
        private boolean isOpen;
        
        public PortResult(InetAddress host, int port, boolean isOpen) {
            this.host = host;
            this.port = port;
            this.isOpen = isOpen;
        }
    }
} 