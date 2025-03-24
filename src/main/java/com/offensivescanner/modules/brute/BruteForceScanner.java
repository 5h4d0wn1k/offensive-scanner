package com.offensivescanner.modules.brute;

import com.offensivescanner.core.ConfigManager;
import com.offensivescanner.core.ScanResults;
import com.offensivescanner.core.Target;
import com.offensivescanner.modules.AbstractScanModule;
import com.offensivescanner.modules.ModuleType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BruteForceScanner module for attempting to brute force credentials for common services.
 */
public class BruteForceScanner extends AbstractScanModule {
    
    private final int timeout;
    private final int threads;
    private final int maxAttempts;
    private final List<String> targetServices;
    private final List<String> usernames;
    private final List<String> passwords;
    
    // Services and their default ports
    private static final Map<String, Integer> SUPPORTED_SERVICES = new HashMap<>();
    
    static {
        SUPPORTED_SERVICES.put("ssh", 22);
        SUPPORTED_SERVICES.put("ftp", 21);
        SUPPORTED_SERVICES.put("telnet", 23);
        SUPPORTED_SERVICES.put("smb", 445);
        SUPPORTED_SERVICES.put("mysql", 3306);
        SUPPORTED_SERVICES.put("mssql", 1433);
        SUPPORTED_SERVICES.put("postgres", 5432);
        SUPPORTED_SERVICES.put("rdp", 3389);
    }
    
    /**
     * Create a new brute force scanner module
     *
     * @param configManager The configuration manager
     * @param scanResults The scan results container
     */
    public BruteForceScanner(ConfigManager configManager, ScanResults scanResults) {
        super(configManager, scanResults, "Brute Force Scanner", 
            "Attempts to brute force credentials for services", ModuleType.BRUTE_FORCE);
        
        this.timeout = configManager.getConfigValue("brute_force", "timeout", 5000);
        this.threads = configManager.getConfigValue("brute_force", "threads", 10);
        this.maxAttempts = configManager.getConfigValue("brute_force", "max_attempts", 500);
        
        // Get target services from config or use defaults
        String servicesStr = configManager.getConfigValue("brute_force", "services", "ssh,ftp,smb");
        this.targetServices = Arrays.asList(servicesStr.split(","));
        
        // Load usernames and passwords from wordlists
        this.usernames = loadWordlist(configManager.getConfigValue("brute_force", "usernames_file", "wordlists/usernames.txt"));
        this.passwords = loadWordlist(configManager.getConfigValue("brute_force", "passwords_file", "wordlists/passwords.txt"));
        
        if (usernames.isEmpty() || passwords.isEmpty()) {
            logWarning("Username or password wordlist is empty. Brute force attacks will be limited.");
        }
    }
    
    @Override
    public void scan(Target target) throws Exception {
        logInfo("Starting brute force scan against " + target.toString());
        
        // Get open ports from previous scans
        Map<InetAddress, Map<Integer, ScanResults.PortInfo>> openPorts = scanResults.getOpenPorts();
        
        if (openPorts.isEmpty()) {
            logWarning("No open ports found for brute forcing. Run port scan first.");
            return;
        }
        
        // Get host addresses
        List<InetAddress> hosts = target.getResolvedAddresses();
        final AtomicInteger credentialsFound = new AtomicInteger(0);
        final AtomicInteger totalAttempts = new AtomicInteger(0);
        
        // Create task list of (host, service, port) combinations to brute force
        List<BruteForceTask> tasks = new ArrayList<>();
        
        // For each target host
        for (InetAddress host : hosts) {
            // Check if this host has open ports
            if (!openPorts.containsKey(host)) {
                continue;
            }
            
            Map<Integer, ScanResults.PortInfo> hostPorts = openPorts.get(host);
            
            // Look for target services
            for (Map.Entry<String, Integer> service : SUPPORTED_SERVICES.entrySet()) {
                String serviceName = service.getKey();
                int defaultPort = service.getValue();
                
                // Skip services that aren't in our target list
                if (!targetServices.contains(serviceName)) {
                    continue;
                }
                
                // Check if the default port is open
                if (hostPorts.containsKey(defaultPort)) {
                    tasks.add(new BruteForceTask(host, serviceName, defaultPort));
                    continue;
                }
                
                // Or look for the service by name in any port
                for (Map.Entry<Integer, ScanResults.PortInfo> portEntry : hostPorts.entrySet()) {
                    int port = portEntry.getKey();
                    ScanResults.PortInfo portInfo = portEntry.getValue();
                    
                    if (portInfo.getService() != null && 
                        portInfo.getService().toLowerCase().contains(serviceName)) {
                        tasks.add(new BruteForceTask(host, serviceName, port));
                        break;
                    }
                }
            }
        }
        
        if (tasks.isEmpty()) {
            logInfo("No suitable services found for brute forcing.");
            return;
        }
        
        logInfo("Found " + tasks.size() + " service(s) to brute force.");
        
        // Use a thread pool for parallel brute forcing
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        
        // Submit brute force tasks
        for (BruteForceTask task : tasks) {
            executor.submit(() -> {
                try {
                    bruteForceService(task.host, task.service, task.port, credentialsFound, totalAttempts);
                } catch (Exception e) {
                    logError("Error brute forcing " + task.service + " on " + 
                            task.host.getHostAddress() + ":" + task.port + ": " + e.getMessage());
                }
            });
        }
        
        // Shutdown and wait for all tasks to complete
        executor.shutdown();
        executor.awaitTermination(30, TimeUnit.MINUTES);
        
        logInfo("Brute force scan completed. Made " + totalAttempts.get() + 
                " attempts and found " + credentialsFound.get() + " valid credentials.");
    }
    
    /**
     * Attempt to brute force a specific service
     *
     * @param host The target host
     * @param service The service name
     * @param port The port number
     * @param credentialsFound Counter for found credentials
     * @param totalAttempts Counter for total attempts
     */
    private void bruteForceService(InetAddress host, String service, int port,
                                  AtomicInteger credentialsFound, AtomicInteger totalAttempts) {
        logInfo("Brute forcing " + service + " on " + host.getHostAddress() + ":" + port);
        
        // In a real implementation, this would try actual authentication
        // For now, we'll simulate the brute force process
        
        int attempts = 0;
        int maxLocalAttempts = Math.min(maxAttempts, usernames.size() * passwords.size());
        
        Collections.shuffle(usernames);
        Collections.shuffle(passwords);
        
        for (String username : usernames) {
            for (String password : passwords) {
                // Limit the number of attempts per service
                if (attempts >= maxLocalAttempts) {
                    logInfo("Reached maximum attempts for " + service + " on " + 
                            host.getHostAddress() + ":" + port);
                    return;
                }
                
                totalAttempts.incrementAndGet();
                attempts++;
                
                if (attempts % 50 == 0) {
                    logInfo("Made " + attempts + " attempts on " + service + " (" + 
                            host.getHostAddress() + ":" + port + ")");
                }
                
                // Simulate an authentication attempt
                // In a real implementation, this would use the appropriate protocol
                if (simulateAuthentication(host, service, port, username, password)) {
                    credentialsFound.incrementAndGet();
                    scanResults.addCredentials(host, service, username, password);
                    
                    logSuccess("Found valid credentials for " + service + " on " + 
                               host.getHostAddress() + ":" + port + " - " +
                               username + ":" + password);
                    
                    // Found credentials for this service, stop trying
                    return;
                }
                
                // Small delay to avoid overwhelming the service
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
        
        logInfo("No valid credentials found for " + service + " on " + 
                host.getHostAddress() + ":" + port + " after " + attempts + " attempts.");
    }
    
    /**
     * Simulate an authentication attempt (placeholder for real implementation)
     * 
     * @param host The target host
     * @param service The service name
     * @param port The port number
     * @param username The username to try
     * @param password The password to try
     * @return true if authentication succeeded
     */
    private boolean simulateAuthentication(InetAddress host, String service, int port, 
                                         String username, String password) {
        // This is a simulation for demonstration
        // In a real implementation, this would attempt to authenticate using the appropriate protocol
        
        // Use the configured timeout for the connection
        logVerbose("Attempting auth with timeout " + timeout + "ms: " + username + "@" + host.getHostAddress());
        
        // For demonstration purposes, we'll use a simple common password check
        // Real credentials have a small chance of success
        if ((username.equals("admin") && password.equals("admin123")) ||
            (username.equals("root") && password.equals("toor")) ||
            (username.equals("administrator") && password.equals("password")) ||
            (Math.random() < 0.001)) { // 0.1% random chance of success
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Load a wordlist from a file
     *
     * @param filename The wordlist file path
     * @return List of words from the file
     */
    private List<String> loadWordlist(String filename) {
        List<String> wordlist = new ArrayList<>();
        
        try {
            File file = new File(filename);
            if (!file.exists()) {
                logWarning("Wordlist file not found: " + filename);
                return wordlist;
            }
            
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        wordlist.add(line);
                    }
                }
            }
            
            logInfo("Loaded " + wordlist.size() + " entries from " + filename);
        } catch (Exception e) {
            logError("Error loading wordlist " + filename + ": " + e.getMessage());
        }
        
        return wordlist;
    }
    
    /**
     * Task representing a service to brute force
     */
    private static class BruteForceTask {
        private final InetAddress host;
        private final String service;
        private final int port;
        
        public BruteForceTask(InetAddress host, String service, int port) {
            this.host = host;
            this.service = service;
            this.port = port;
        }
    }
} 