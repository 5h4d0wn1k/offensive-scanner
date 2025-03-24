package com.offensivescanner.core;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a target for scanning, which can be an IP address, hostname, or a range of IPs.
 */
public class Target {
    
    // Regular expression patterns for target types
    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    
    private static final Pattern CIDR_PATTERN = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,2})$");
    
    private static final Pattern IP_RANGE_PATTERN = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})-(\\d{1,3})$");
    
    private final String originalTarget;
    private final TargetType targetType;
    private List<InetAddress> resolvedAddresses;
    
    /**
     * Types of targets supported by the scanner
     */
    public enum TargetType {
        SINGLE_IP,       // Single IP address (e.g., 192.168.1.1)
        HOSTNAME,        // Hostname (e.g., example.com)
        CIDR_RANGE,      // CIDR notation (e.g., 192.168.1.0/24)
        IP_RANGE,        // IP range (e.g., 192.168.1.1-10)
        URL              // URL (e.g., https://example.com)
    }
    
    /**
     * Create a target from a string representation
     * 
     * @param targetStr The target string
     * @throws IllegalArgumentException if the target is invalid
     */
    public Target(String targetStr) {
        this.originalTarget = targetStr.trim();
        this.targetType = determineTargetType(originalTarget);
        this.resolvedAddresses = new ArrayList<>();
        
        // Resolve the target to IP addresses
        resolveTarget();
    }
    
    /**
     * Parse a target string and create a Target object
     * 
     * @param targetStr The target string
     * @return A new Target object
     * @throws IllegalArgumentException if the target is invalid
     */
    public static Target parse(String targetStr) {
        return new Target(targetStr);
    }
    
    /**
     * Determine the type of the target
     * 
     * @param targetStr The target string
     * @return The target type
     * @throws IllegalArgumentException if the target is invalid
     */
    private TargetType determineTargetType(String targetStr) {
        // Check for URL
        if (targetStr.startsWith("http://") || targetStr.startsWith("https://")) {
            return TargetType.URL;
        }
        
        // Check for IP address
        Matcher ipMatcher = IP_PATTERN.matcher(targetStr);
        if (ipMatcher.matches()) {
            // Validate IP address components
            boolean valid = true;
            for (int i = 1; i <= 4; i++) {
                int octet = Integer.parseInt(ipMatcher.group(i));
                if (octet < 0 || octet > 255) {
                    valid = false;
                    break;
                }
            }
            
            if (valid) {
                return TargetType.SINGLE_IP;
            }
        }
        
        // Check for CIDR notation
        Matcher cidrMatcher = CIDR_PATTERN.matcher(targetStr);
        if (cidrMatcher.matches()) {
            int prefix = Integer.parseInt(cidrMatcher.group(5));
            if (prefix >= 0 && prefix <= 32) {
                return TargetType.CIDR_RANGE;
            }
        }
        
        // Check for IP range
        Matcher rangeMatcher = IP_RANGE_PATTERN.matcher(targetStr);
        if (rangeMatcher.matches()) {
            return TargetType.IP_RANGE;
        }
        
        // If none of the above, assume it's a hostname
        if (isValidHostname(targetStr)) {
            return TargetType.HOSTNAME;
        }
        
        throw new IllegalArgumentException("Invalid target: " + targetStr);
    }
    
    /**
     * Check if a string is a valid hostname
     * 
     * @param hostname The hostname string
     * @return true if the hostname is valid
     */
    private boolean isValidHostname(String hostname) {
        // Basic hostname validation, could be enhanced
        if (hostname.isEmpty() || hostname.length() > 255) {
            return false;
        }
        
        String[] labels = hostname.split("\\.");
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                return false;
            }
            
            if (!label.matches("^[a-zA-Z0-9-]+$")) {
                return false;
            }
            
            if (label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Resolve the target to IP addresses
     * 
     * @throws IllegalArgumentException if the target cannot be resolved
     */
    private void resolveTarget() {
        try {
            switch (targetType) {
                case SINGLE_IP:
                    resolvedAddresses.add(InetAddress.getByName(originalTarget));
                    break;
                    
                case HOSTNAME:
                    resolvedAddresses.addAll(Arrays.asList(InetAddress.getAllByName(originalTarget)));
                    break;
                    
                case URL:
                    // Extract the hostname from the URL
                    String hostname = originalTarget.replaceFirst("^https?://", "")
                                                  .replaceFirst("/.*$", "");
                    resolvedAddresses.addAll(Arrays.asList(InetAddress.getAllByName(hostname)));
                    break;
                    
                case CIDR_RANGE:
                    resolvedAddresses.addAll(expandCidrRange(originalTarget));
                    break;
                    
                case IP_RANGE:
                    resolvedAddresses.addAll(expandIpRange(originalTarget));
                    break;
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Cannot resolve target: " + originalTarget, e);
        }
        
        if (resolvedAddresses.isEmpty()) {
            throw new IllegalArgumentException("No IP addresses resolved for target: " + originalTarget);
        }
    }
    
    /**
     * Expand a CIDR range into individual IP addresses
     * 
     * @param cidrRange The CIDR range string
     * @return List of IP addresses in the range
     * @throws UnknownHostException if the range is invalid
     */
    private List<InetAddress> expandCidrRange(String cidrRange) throws UnknownHostException {
        List<InetAddress> addresses = new ArrayList<>();
        
        Matcher matcher = CIDR_PATTERN.matcher(cidrRange);
        if (matcher.matches()) {
            int prefix = Integer.parseInt(matcher.group(5));
            
            // Only support reasonable CIDR ranges to avoid generating too many addresses
            if (prefix < 16) {
                throw new IllegalArgumentException("CIDR prefix must be at least 16 for safety");
            }
            
            // Use InetAddress to get bytes for network address
            String networkAddrStr = matcher.group(1) + "." + matcher.group(2) + "." + 
                                   matcher.group(3) + "." + matcher.group(4);
            InetAddress networkAddr = InetAddress.getByName(networkAddrStr);
            byte[] networkBytes = networkAddr.getAddress();
            
            // Calculate network and broadcast addresses
            int numAddresses = 1 << (32 - prefix);
            
            // Generate all addresses in the range
            for (int i = 0; i < numAddresses; i++) {
                byte[] hostBytes = networkBytes.clone();
                
                // Apply the host bits
                for (int j = 0; j < 4; j++) {
                    int shift = 8 * (3 - j);
                    int mask = 0xFF << shift;
                    int hostPart = i & mask;
                    hostBytes[j] |= (hostPart >> shift) & 0xFF;
                }
                
                InetAddress hostAddr = InetAddress.getByAddress(hostBytes);
                addresses.add(hostAddr);
            }
        } else {
            throw new IllegalArgumentException("Invalid CIDR range: " + cidrRange);
        }
        
        return addresses;
    }
    
    /**
     * Expand an IP range into individual IP addresses
     * 
     * @param ipRange The IP range string
     * @return List of IP addresses in the range
     * @throws UnknownHostException if the range is invalid
     */
    private List<InetAddress> expandIpRange(String ipRange) throws UnknownHostException {
        List<InetAddress> addresses = new ArrayList<>();
        
        Matcher matcher = IP_RANGE_PATTERN.matcher(ipRange);
        if (matcher.matches()) {
            String baseIp = matcher.group(1) + "." + matcher.group(2) + "." + 
                           matcher.group(3) + ".";
            int startIp = Integer.parseInt(matcher.group(4));
            int endIp = Integer.parseInt(matcher.group(5));
            
            // Validate range
            if (startIp < 0 || startIp > 255 || endIp < 0 || endIp > 255 || startIp > endIp) {
                throw new IllegalArgumentException("Invalid IP range: " + ipRange);
            }
            
            // Only support reasonable ranges to avoid generating too many addresses
            if (endIp - startIp > 255) {
                throw new IllegalArgumentException("IP range too large: " + ipRange);
            }
            
            // Generate all addresses in the range
            for (int i = startIp; i <= endIp; i++) {
                String ip = baseIp + i;
                addresses.add(InetAddress.getByName(ip));
            }
        } else {
            throw new IllegalArgumentException("Invalid IP range: " + ipRange);
        }
        
        return addresses;
    }
    
    /**
     * Get the original target string
     * 
     * @return The original target string
     */
    public String getOriginalTarget() {
        return originalTarget;
    }
    
    /**
     * Get the target type
     * 
     * @return The target type
     */
    public TargetType getTargetType() {
        return targetType;
    }
    
    /**
     * Get the resolved IP addresses for this target
     * 
     * @return List of resolved IP addresses
     */
    public List<InetAddress> getResolvedAddresses() {
        return resolvedAddresses;
    }
    
    @Override
    public String toString() {
        return originalTarget + " (" + targetType + ", " + resolvedAddresses.size() + " addresses)";
    }
} 