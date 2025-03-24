package com.offensivescanner.modules.ssl;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.core.VulnerabilitySeverity;
import com.offensivescanner.modules.AbstractScanModule;
import com.offensivescanner.modules.ModuleType;

import java.net.InetAddress;
import java.util.*;

/**
 * SSLScanner module for detecting SSL/TLS vulnerabilities and misconfigurations.
 */
public class SSLScanner extends AbstractScanModule {
    
    private final int timeout;
    private final boolean checkCertificates;
    private final boolean checkProtocols;
    private final boolean checkCiphers;
    
    /**
     * Create a new SSL/TLS scanner module
     *
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     */
    public SSLScanner(ConfigManager configManager, ScanResults scanResults) {
        super(configManager, scanResults, "SSL/TLS Scanner", 
            "Scans for SSL/TLS vulnerabilities and misconfigurations", ModuleType.SSL_ANALYSIS);
        
        this.timeout = configManager.getConfigValue("ssl_scan", "timeout", 10000);
        this.checkCertificates = configManager.getConfigValue("ssl_scan", "check_certificates", true);
        this.checkProtocols = configManager.getConfigValue("ssl_scan", "check_protocols", true);
        this.checkCiphers = configManager.getConfigValue("ssl_scan", "check_ciphers", true);
    }
    
    @Override
    public void scan(Target target) throws Exception {
        logInfo("Starting SSL/TLS scan against " + target.toString());
        
        // Get open ports from previous scans
        Map<InetAddress, Map<Integer, ScanResults.PortInfo>> openPorts = scanResults.getOpenPorts();
        
        if (openPorts.isEmpty()) {
            logWarning("No open ports found for SSL/TLS scanning. Run port scan first.");
            return;
        }
        
        // SSL/TLS ports to check
        List<Integer> sslPorts = Arrays.asList(443, 8443, 465, 636, 993, 995);
        
        // Get host addresses
        List<InetAddress> hosts = target.getResolvedAddresses();
        int vulnerabilitiesFound = 0;
        
        // For each target host
        for (InetAddress host : hosts) {
            // Check if this host has open ports
            if (!openPorts.containsKey(host)) {
                continue;
            }
            
            Map<Integer, ScanResults.PortInfo> hostPorts = openPorts.get(host);
            
            // Check each potentially SSL/TLS enabled port
            for (Map.Entry<Integer, ScanResults.PortInfo> entry : hostPorts.entrySet()) {
                int port = entry.getKey();
                ScanResults.PortInfo portInfo = entry.getValue();
                
                // Check if this port is a standard SSL port or has SSL/TLS in the service name
                if (sslPorts.contains(port) || 
                    (portInfo.getService() != null && 
                     (portInfo.getService().toLowerCase().contains("ssl") || 
                      portInfo.getService().toLowerCase().contains("tls") ||
                      portInfo.getService().toLowerCase().contains("https")))) {
                    
                    logInfo("Checking SSL/TLS on " + host.getHostAddress() + ":" + port);
                    
                    // Perform the SSL/TLS checks
                    vulnerabilitiesFound += checkSSL(host, port);
                }
            }
        }
        
        if (vulnerabilitiesFound == 0) {
            logInfo("No SSL/TLS vulnerabilities detected.");
        } else {
            logInfo("SSL/TLS scan completed. Found " + vulnerabilitiesFound + " vulnerabilities or issues.");
        }
    }
    
    /**
     * Check SSL/TLS configuration on a specific host and port
     * 
     * @param host The host to check
     * @param port The port to check
     * @return Number of vulnerabilities found
     */
    private int checkSSL(InetAddress host, int port) {
        int vulnerabilitiesFound = 0;
        
        try {
            // Log using the timeout configuration
            logInfo("Using SSL connection timeout of " + timeout + "ms");
            
            // In a real implementation, this would use SSL libraries to check certificates, protocols, and ciphers
            // For this example, we'll simulate the checks with common vulnerabilities
            
            // Certificate checks
            if (checkCertificates) {
                vulnerabilitiesFound += checkCertificate(host, port);
            }
            
            // Protocol checks
            if (checkProtocols) {
                vulnerabilitiesFound += checkProtocols(host, port);
            }
            
            // Cipher checks
            if (checkCiphers) {
                vulnerabilitiesFound += checkCiphers(host, port);
            }
            
        } catch (Exception e) {
            logError("Error checking SSL/TLS on " + host.getHostAddress() + ":" + port + ": " + e.getMessage());
        }
        
        return vulnerabilitiesFound;
    }
    
    /**
     * Check certificate validity and issues
     * 
     * @param host The host to check
     * @param port The port to check
     * @return Number of certificate issues found
     */
    private int checkCertificate(InetAddress host, int port) {
        logInfo("Checking certificate for " + host.getHostAddress() + ":" + port);
        int issuesFound = 0;
        
        // Simulate certificate checks
        // In a real implementation, this would examine the certificate chain, validity, etc.
        
        // Check 1: Expired certificate (20% chance)
        if (Math.random() < 0.2) {
            issuesFound++;
            String vulnName = "Expired SSL Certificate";
            String desc = "The SSL certificate for this service has expired";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.HIGH, host, port, 
                null, "Renew the SSL certificate from the certificate authority"
            ));
        }
        
        // Check 2: Self-signed certificate (30% chance)
        if (Math.random() < 0.3) {
            issuesFound++;
            String vulnName = "Self-Signed SSL Certificate";
            String desc = "The SSL certificate is self-signed and not from a trusted CA";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.MEDIUM, host, port,
                null, "Obtain a certificate from a trusted certificate authority"
            ));
        }
        
        // Check 3: Hostname mismatch (25% chance)
        if (Math.random() < 0.25) {
            issuesFound++;
            String vulnName = "SSL Certificate Hostname Mismatch";
            String desc = "The SSL certificate's CN/SAN does not match the hostname";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.MEDIUM, host, port,
                null, "Obtain a certificate with the correct hostname in CN/SAN fields"
            ));
        }
        
        return issuesFound;
    }
    
    /**
     * Check supported SSL/TLS protocols for vulnerabilities
     * 
     * @param host The host to check
     * @param port The port to check
     * @return Number of protocol issues found
     */
    private int checkProtocols(InetAddress host, int port) {
        logInfo("Checking SSL/TLS protocols for " + host.getHostAddress() + ":" + port);
        int issuesFound = 0;
        
        // Simulate protocol checks
        // In a real implementation, this would attempt connections with various protocols
        
        // Check 1: SSLv2 enabled (10% chance)
        if (Math.random() < 0.1) {
            issuesFound++;
            String vulnName = "SSLv2 Protocol Enabled";
            String desc = "The deprecated and insecure SSLv2 protocol is enabled";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.HIGH, host, port,
                null, "Disable SSLv2 in the server configuration"
            ));
        }
        
        // Check 2: SSLv3 enabled (POODLE) (20% chance)
        if (Math.random() < 0.2) {
            issuesFound++;
            String vulnName = "SSLv3 Protocol Enabled (POODLE)";
            String desc = "The vulnerable SSLv3 protocol is enabled (POODLE vulnerability)";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.HIGH, host, port,
                "CVE-2014-3566", "Disable SSLv3 in the server configuration"
            ));
        }
        
        // Check 3: TLS 1.0 enabled (40% chance)
        if (Math.random() < 0.4) {
            issuesFound++;
            String vulnName = "TLS 1.0 Protocol Enabled";
            String desc = "The outdated TLS 1.0 protocol is enabled";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.MEDIUM, host, port,
                null, "Disable TLS 1.0 in the server configuration"
            ));
        }
        
        return issuesFound;
    }
    
    /**
     * Check supported cipher suites for vulnerabilities
     * 
     * @param host The host to check
     * @param port The port to check
     * @return Number of cipher issues found
     */
    private int checkCiphers(InetAddress host, int port) {
        logInfo("Checking SSL/TLS cipher suites for " + host.getHostAddress() + ":" + port);
        int issuesFound = 0;
        
        // Simulate cipher checks
        // In a real implementation, this would enumerate supported ciphers
        
        // Check 1: Weak ciphers (RC4) (30% chance)
        if (Math.random() < 0.3) {
            issuesFound++;
            String vulnName = "RC4 Cipher Enabled";
            String desc = "The weak RC4 cipher is enabled";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.HIGH, host, port,
                null, "Disable RC4 ciphers in the server configuration"
            ));
        }
        
        // Check 2: Weak ciphers (DES/3DES) (25% chance)
        if (Math.random() < 0.25) {
            issuesFound++;
            String vulnName = "DES/3DES Ciphers Enabled";
            String desc = "The weak DES/3DES ciphers are enabled";
            logWarning("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.MEDIUM, host, port,
                null, "Disable DES/3DES ciphers in the server configuration"
            ));
        }
        
        // Check 3: EXPORT ciphers (15% chance)
        if (Math.random() < 0.15) {
            issuesFound++;
            String vulnName = "EXPORT Grade Ciphers Enabled";
            String desc = "The extremely weak EXPORT grade ciphers are enabled (FREAK vulnerability)";
            logError("Found issue: " + vulnName);
            
            scanResults.addVulnerability(host, new ScanResults.Vulnerability(
                vulnName, desc, VulnerabilitySeverity.CRITICAL, host, port,
                "CVE-2015-0204", "Disable EXPORT ciphers in the server configuration"
            ));
        }
        
        return issuesFound;
    }
} 