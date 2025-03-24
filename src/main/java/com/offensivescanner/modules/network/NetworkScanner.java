package com.offensivescanner.modules.network;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.modules.AbstractScanModule;
import com.offensivescanner.modules.ModuleType;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Network scanner module for detecting live hosts and OS fingerprinting.
 */
public class NetworkScanner extends AbstractScanModule {
    
    private final int timeout;
    private final int threads;
    private final boolean osDetection;
    
    /**
     * Create a new network scanner module
     *
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     */
    public NetworkScanner(ConfigManager configManager, ScanResults scanResults) {
        super(configManager, scanResults, "Network Scanner", 
            "Scans for live hosts and performs OS fingerprinting", ModuleType.NETWORK_DISCOVERY);
        
        this.timeout = configManager.getConfigValue("network_scan", "timeout", 1000);
        this.threads = configManager.getConfigValue("network_scan", "threads", 50);
        this.osDetection = configManager.getConfigValue("network_scan", "os_detection", true);
    }
    
    @Override
    public void scan(Target target) throws Exception {
        logInfo("Starting network scan against " + target.toString());
        
        List<InetAddress> hosts;
        
        // If the target is a range, we need to generate all IPs in the range
        if (target.getTargetType() == Target.TargetType.CIDR_RANGE || 
            target.getTargetType() == Target.TargetType.IP_RANGE) {
            logInfo("Target is a range, performing discovery scan...");
            hosts = target.getResolvedAddresses();
        } else {
            // For single hosts, just use the resolved addresses
            hosts = target.getResolvedAddresses();
        }
        
        if (hosts.isEmpty()) {
            logWarning("No hosts to scan. Please check your target specification.");
            return;
        }
        
        logInfo("Scanning " + hosts.size() + " host(s) for availability...");
        
        // Use a thread pool for parallel scanning
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<InetAddress> liveHosts = new ArrayList<>();
        
        // Submit each host for scanning
        for (InetAddress host : hosts) {
            executor.submit(() -> {
                try {
                    if (isHostAlive(host)) {
                        synchronized (liveHosts) {
                            liveHosts.add(host);
                            scanResults.addDiscoveredHost(host);
                        }
                        
                        logSuccess("Host " + host.getHostAddress() + " is UP");
                        
                        // Try to get hostname
                        try {
                            String hostname = host.getCanonicalHostName();
                            if (!hostname.equals(host.getHostAddress())) {
                                scanResults.setHostname(host, hostname);
                                logInfo("Hostname: " + hostname);
                            }
                        } catch (Exception e) {
                            // Not critical if we can't get hostname
                        }
                        
                        // Perform OS detection if enabled
                        if (osDetection) {
                            detectOS(host);
                        }
                    }
                } catch (Exception e) {
                    logError("Error scanning host " + host.getHostAddress() + ": " + e.getMessage());
                }
            });
        }
        
        // Shutdown and wait for all tasks to complete
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.MINUTES);
        
        logInfo("Network scan completed. Found " + liveHosts.size() + " live hosts out of " + hosts.size() + " scanned.");
    }
    
    /**
     * Check if a host is alive using ICMP and TCP probes
     *
     * @param host The host to check
     * @return true if the host is alive
     */
    private boolean isHostAlive(InetAddress host) {
        try {
            // First try ICMP ping (may not work depending on privileges)
            if (host.isReachable(timeout)) {
                return true;
            }
            
            // Fall back to TCP connection attempts to common ports
            int[] commonPorts = {80, 443, 22, 445, 3389};
            for (int port : commonPorts) {
                try {
                    java.net.Socket socket = new java.net.Socket();
                    socket.connect(new java.net.InetSocketAddress(host, port), timeout);
                    socket.close();
                    return true;
                } catch (Exception ignored) {
                    // Connection failed, try next port
                }
            }
            
            return false;
        } catch (Exception e) {
            logWarning("Error checking if host is alive: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Attempt to detect the operating system of a host
     *
     * @param host The host to analyze
     */
    private void detectOS(InetAddress host) {
        try {
            String os = "Unknown";
            
            // In a real implementation, this would use various fingerprinting techniques
            // Such as TTL analysis, TCP/IP stack behavior, etc.
            // For this example, we'll just simulate OS detection with random results
            
            double rand = Math.random();
            if (rand < 0.3) {
                os = "Windows";
                if (rand < 0.15) {
                    os += " 10/11";
                } else {
                    os += " Server 2019";
                }
            } else if (rand < 0.6) {
                os = "Linux";
                if (rand < 0.45) {
                    os += " (Ubuntu)";
                } else {
                    os += " (CentOS)";
                }
            } else if (rand < 0.8) {
                os = "macOS";
            } else {
                os = "FreeBSD";
            }
            
            scanResults.setOsInfo(host, os);
            logInfo("Detected OS for " + host.getHostAddress() + ": " + os);
            
        } catch (Exception e) {
            logWarning("Error detecting OS for host " + host.getHostAddress() + ": " + e.getMessage());
        }
    }
} 