// ScanResults.java 

package com.offensivescanner.core;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Container for scan results that collects and organizes all findings from scanning modules.
 */
public class ScanResults {

    private Target target;
    private long scanStartTime;
    private long scanEndTime;
    
    // Open ports and services
    private final Map<InetAddress, Map<Integer, PortInfo>> openPorts = new ConcurrentHashMap<>();
    
    // Discovered vulnerabilities
    private final Map<InetAddress, List<Vulnerability>> vulnerabilities = new ConcurrentHashMap<>();
    
    // Web vulnerabilities
    private final List<WebVulnerability> webVulnerabilities = new ArrayList<>();
    
    // Credentials found via brute force
    private final Map<InetAddress, Map<String, String>> credentials = new HashMap<>();
    
    // DNS records
    private final List<DnsRecord> dnsRecords = new ArrayList<>();
    
    // Network hosts discovered
    private final Set<InetAddress> discoveredHosts = new HashSet<>();
    
    // Map of host -> OS info
    private final Map<InetAddress, String> osInfo = new ConcurrentHashMap<>();
    
    // Map of host -> hostname
    private final Map<InetAddress, String> hostnames = new ConcurrentHashMap<>();
    
    /**
     * Create a new empty scan results container
     */
    public ScanResults() {
        // Empty constructor for initial creation
    }

    /**
     * Create a new scan results container for the specified target
     * 
     * @param target The scan target
     */
    public ScanResults(Target target) {
        this.target = target;
    }
    
    /**
     * Get the scan target
     * 
     * @return The target
     */
    public Target getTarget() {
        return target;
    }

    /**
     * Set the scan target
     * 
     * @param target The target to set
     */
    public void setTarget(Target target) {
        this.target = target;
    }
    
    /**
     * Set the scan start time
     * 
     * @param scanStartTime Timestamp in milliseconds
     */
    public void setScanStartTime(long scanStartTime) {
        this.scanStartTime = scanStartTime;
    }
    
    /**
     * Set the scan end time
     * 
     * @param scanEndTime Timestamp in milliseconds
     */
    public void setScanEndTime(long scanEndTime) {
        this.scanEndTime = scanEndTime;
    }
    
    /**
     * Get the scan start time
     * 
     * @return Timestamp in milliseconds
     */
    public long getScanStartTime() {
        return scanStartTime;
    }
    
    /**
     * Get the scan end time
     * 
     * @return Timestamp in milliseconds
     */
    public long getScanEndTime() {
        return scanEndTime;
    }
    
    /**
     * Get the scan duration
     * 
     * @return Duration in milliseconds
     */
    public long getScanDuration() {
        return scanEndTime - scanStartTime;
    }
    
    /**
     * Add a port that was found to be open
     * 
     * @param host The host IP
     * @param port The open port number
     * @param protocol The protocol (TCP/UDP)
     * @param service The detected service name (if known)
     * @param version The detected service version (if known)
     */
    public void addOpenPort(InetAddress host, int port, String protocol, String service, String version) {
        if (!openPorts.containsKey(host)) {
            openPorts.put(host, new ConcurrentHashMap<>());
        }
        
        openPorts.get(host).put(port, new PortInfo(port, protocol, service, version));
    }
    
    /**
     * Get all open ports for all hosts
     * 
     * @return Map of hosts to open ports
     */
    public Map<InetAddress, Map<Integer, PortInfo>> getOpenPorts() {
        return openPorts;
    }
    
    /**
     * Get the count of open ports across all hosts
     * 
     * @return Total open port count
     */
    public int getOpenPortCount() {
        int count = 0;
        for (Map<Integer, PortInfo> hostPorts : openPorts.values()) {
            count += hostPorts.size();
        }
        return count;
    }
    
    /**
     * Add a vulnerability that was found
     * 
     * @param host The host with the vulnerability
     * @param vulnerability The vulnerability details
     */
    public void addVulnerability(InetAddress host, Vulnerability vulnerability) {
        if (!vulnerabilities.containsKey(host)) {
            vulnerabilities.put(host, new ArrayList<>());
        }
        
        vulnerabilities.get(host).add(vulnerability);
    }
    
    /**
     * Get all vulnerabilities for all hosts
     * 
     * @return Map of hosts to vulnerabilities
     */
    public Map<InetAddress, List<Vulnerability>> getVulnerabilities() {
        return vulnerabilities;
    }
    
    /**
     * Get the count of vulnerabilities with a specific severity
     * 
     * @param severity The severity level
     * @return Count of vulnerabilities with the specified severity
     */
    public int getVulnerabilityCount(VulnerabilitySeverity severity) {
        int count = 0;
        for (List<Vulnerability> hostVulns : vulnerabilities.values()) {
            for (Vulnerability vuln : hostVulns) {
                if (vuln.getSeverity() == severity) {
                    count++;
                }
            }
        }
        return count;
    }
    
    /**
     * Add a web vulnerability that was found
     * 
     * @param webVulnerability The web vulnerability
     */
    public void addWebVulnerability(WebVulnerability webVulnerability) {
        webVulnerabilities.add(webVulnerability);
    }
    
    /**
     * Get all web vulnerabilities
     * 
     * @return List of web vulnerabilities
     */
    public List<WebVulnerability> getWebVulnerabilities() {
        return webVulnerabilities;
    }
    
    /**
     * Get the count of web vulnerabilities
     * 
     * @return Count of web vulnerabilities
     */
    public int getWebVulnerabilityCount() {
        return webVulnerabilities.size();
    }
    
    /**
     * Add credentials found via brute force
     * 
     * @param host The host
     * @param service The service name (e.g., "ssh", "ftp")
     * @param username The username
     * @param password The password
     */
    public void addCredentials(InetAddress host, String service, String username, String password) {
        Map<String, String> serviceCredentials = credentials.computeIfAbsent(host, k -> new HashMap<>());
        serviceCredentials.put(service + ":" + username, password);
    }
    
    /**
     * Get all credentials found for all hosts
     * 
     * @return Map of hosts to credentials
     */
    public Map<InetAddress, Map<String, String>> getCredentials() {
        return credentials;
    }
    
    /**
     * Add a DNS record that was found
     * 
     * @param dnsRecord The DNS record
     */
    public void addDnsRecord(DnsRecord dnsRecord) {
        dnsRecords.add(dnsRecord);
    }
    
    /**
     * Get all DNS records
     * 
     * @return List of DNS records
     */
    public List<DnsRecord> getDnsRecords() {
        return dnsRecords;
    }
    
    /**
     * Add a host that was discovered on the network
     * 
     * @param host The host IP
     */
    public void addDiscoveredHost(InetAddress host) {
        discoveredHosts.add(host);
    }
    
    /**
     * Get all discovered hosts
     * 
     * @return Set of discovered host IPs
     */
    public Set<InetAddress> getDiscoveredHosts() {
        return discoveredHosts;
    }
    
    /**
     * Set the OS information for a host
     * 
     * @param host The host
     * @param os The OS information
     */
    public void setOsInfo(InetAddress host, String os) {
        osInfo.put(host, os);
    }
    
    /**
     * Get the OS information for all hosts
     * 
     * @return Map of hosts to OS information
     */
    public Map<InetAddress, String> getOsInfo() {
        return osInfo;
    }
    
    /**
     * Set the hostname for a host
     * 
     * @param host The host
     * @param hostname The hostname
     */
    public void setHostname(InetAddress host, String hostname) {
        hostnames.put(host, hostname);
    }
    
    /**
     * Get the hostnames for all hosts
     * 
     * @return Map of hosts to hostnames
     */
    public Map<InetAddress, String> getHostnames() {
        return hostnames;
    }
    
    /**
     * Get a summary of the scan results
     * 
     * @return A string representation of the scan results summary
     */
    public String getSummary() {
        StringBuilder summary = new StringBuilder();
        
        summary.append("Scan Results Summary:\n");
        summary.append("=====================\n\n");
        
        summary.append("Hosts scanned: ").append(openPorts.size()).append("\n");
        summary.append("Total open ports: ").append(countTotalOpenPorts()).append("\n");
        summary.append("Total vulnerabilities: ").append(countTotalVulnerabilities()).append("\n\n");
        
        for (Map.Entry<InetAddress, Map<Integer, PortInfo>> hostEntry : openPorts.entrySet()) {
            InetAddress host = hostEntry.getKey();
            Map<Integer, PortInfo> ports = hostEntry.getValue();
            
            summary.append("Host: ").append(host.getHostAddress());
            if (hostnames.containsKey(host)) {
                summary.append(" (").append(hostnames.get(host)).append(")");
            }
            summary.append("\n");
            
            if (osInfo.containsKey(host)) {
                summary.append("OS: ").append(osInfo.get(host)).append("\n");
            }
            
            summary.append("Open ports: ").append(ports.size()).append("\n");
            
            for (PortInfo portInfo : ports.values()) {
                summary.append("  ").append(portInfo.port).append("/").append(portInfo.protocol);
                if (portInfo.service != null && !portInfo.service.isEmpty()) {
                    summary.append(" - ").append(portInfo.service);
                    if (portInfo.version != null && !portInfo.version.isEmpty()) {
                        summary.append(" (").append(portInfo.version).append(")");
                    }
                }
                summary.append("\n");
            }
            
            if (vulnerabilities.containsKey(host) && !vulnerabilities.get(host).isEmpty()) {
                List<Vulnerability> hostVulns = vulnerabilities.get(host);
                summary.append("Vulnerabilities: ").append(hostVulns.size()).append("\n");
                
                for (Vulnerability vuln : hostVulns) {
                    summary.append("  ").append(vuln.severity).append(": ")
                           .append(vuln.name).append(" - ").append(vuln.description).append("\n");
                }
            }
            
            summary.append("\n");
        }
        
        return summary.toString();
    }
    
    /**
     * Count the total number of open ports across all hosts
     * 
     * @return Total count of open ports
     */
    private int countTotalOpenPorts() {
        int count = 0;
        for (Map<Integer, PortInfo> hostPorts : openPorts.values()) {
            count += hostPorts.size();
        }
        return count;
    }
    
    /**
     * Count the total number of vulnerabilities across all hosts
     * 
     * @return Total count of vulnerabilities
     */
    private int countTotalVulnerabilities() {
        int count = 0;
        for (List<Vulnerability> hostVulns : vulnerabilities.values()) {
            count += hostVulns.size();
        }
        return count;
    }
    
    /**
     * Class representing information about an open port
     */
    public static class PortInfo {
        private final int port;
        private final String protocol;
        private final String service;
        private final String version;
        
        public PortInfo(int port, String protocol, String service, String version) {
            this.port = port;
            this.protocol = protocol;
            this.service = service;
            this.version = version;
        }
        
        public int getPort() {
            return port;
        }
        
        public String getProtocol() {
            return protocol;
        }
        
        public String getService() {
            return service;
        }
        
        public String getVersion() {
            return version;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(port).append("/").append(protocol);
            
            if (service != null && !service.isEmpty()) {
                sb.append(" (").append(service);
                
                if (version != null && !version.isEmpty()) {
                    sb.append(" ").append(version);
                }
                
                sb.append(")");
            }
            
            return sb.toString();
        }
    }
    
    /**
     * Class representing a vulnerability
     */
    public static class Vulnerability {
        private final String name;
        private final String description;
        private final VulnerabilitySeverity severity;
        private final InetAddress host;
        private final Integer port;
        private final String cveId;
        private final String remediation;
        
        public Vulnerability(String name, String description, VulnerabilitySeverity severity,
                           InetAddress host, Integer port, String cveId, String remediation) {
            this.name = name;
            this.description = description;
            this.severity = severity;
            this.host = host;
            this.port = port;
            this.cveId = cveId;
            this.remediation = remediation;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public VulnerabilitySeverity getSeverity() {
            return severity;
        }
        
        public InetAddress getHost() {
            return host;
        }
        
        public Integer getPort() {
            return port;
        }
        
        public String getCveId() {
            return cveId;
        }
        
        public String getRemediation() {
            return remediation;
        }
    }
    
    /**
     * Class representing a web vulnerability
     */
    public static class WebVulnerability {
        private final String name;
        private final String description;
        private final VulnerabilitySeverity severity;
        private final String url;
        private final String parameter;
        private final String payload;
        private final String remediation;
        
        public WebVulnerability(String name, String description, VulnerabilitySeverity severity,
                              String url, String parameter, String payload, String remediation) {
            this.name = name;
            this.description = description;
            this.severity = severity;
            this.url = url;
            this.parameter = parameter;
            this.payload = payload;
            this.remediation = remediation;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public VulnerabilitySeverity getSeverity() {
            return severity;
        }
        
        public String getUrl() {
            return url;
        }
        
        public String getParameter() {
            return parameter;
        }
        
        public String getPayload() {
            return payload;
        }
        
        public String getRemediation() {
            return remediation;
        }
    }
    
    /**
     * Class representing a DNS record
     */
    public static class DnsRecord {
        private final String hostname;
        private final String type;
        private final String value;
        private final long ttl;
        
        public DnsRecord(String hostname, String type, String value, long ttl) {
            this.hostname = hostname;
            this.type = type;
            this.value = value;
            this.ttl = ttl;
        }
        
        public String getHostname() {
            return hostname;
        }
        
        public String getType() {
            return type;
        }
        
        public String getValue() {
            return value;
        }
        
        public long getTtl() {
            return ttl;
        }
    }
} 
