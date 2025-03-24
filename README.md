# Offensive Scanner

A comprehensive Java-based offensive security scanning tool designed for security professionals, penetration testers, and ethical hackers.

> **DISCLAIMER**: This tool should only be used for authorized security testing and educational purposes. Unauthorized scanning and testing against systems you don't have permission to test is illegal in most jurisdictions.

## Features

- **Port Scanning**: Detect open ports and running services
- **Vulnerability Scanning**: Identify common security vulnerabilities
- **Banner Grabbing**: Retrieve service banners to identify software versions
- **Network Enumeration**: Map network topology and discover devices
- **OS Detection**: Identify operating systems of target hosts
- **Service Enumeration**: Detailed service version detection
- **Web Application Scanning**: Detect common web vulnerabilities
- **Brute Force Capabilities**: Password testing against common services
- **DNS Enumeration**: Domain and subdomain discovery
- **SSL/TLS Analysis**: Identify weak ciphers and certificate issues
- **Custom Exploitation Modules**: Run basic exploitation routines
- **Reporting**: Generate detailed HTML and PDF reports
- **Result Database**: Store scan results for comparison and tracking

## Requirements

- Java 11 or higher
- Maven for building
- Sufficient permissions for network operations (some features may require administrative/root privileges)

## Building

```bash
mvn clean package
```

This will create two JAR files in the `target` directory:
- `offensive-scanner-1.0-SNAPSHOT.jar`: The compiled JAR without dependencies
- `offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar`: The compiled JAR with all dependencies included

## Usage

### Simplified Commands

#### Windows

A simplified command interface is provided through the `scan.bat` script for Windows users:

```bash
scan.bat TARGET SCAN_TYPE [report]
```

Examples:
```bash
# Basic port scan
scan.bat 192.168.1.1 port

# Web application scan with report generation
scan.bat example.com web report

# Network discovery scan
scan.bat 192.168.1.0/24 net

# Full scan with report generation
scan.bat 192.168.1.1 full report
```

#### Linux/Mac

For Linux and Mac users, use the `scan.sh` script:

```bash
# Make the script executable first
chmod +x scan.sh

# Then run your commands
./scan.sh TARGET SCAN_TYPE [report]
```

Examples:
```bash
# Basic port scan
./scan.sh 192.168.1.1 port

# Web application scan with report generation
./scan.sh example.com web report
```

#### Available Scan Types

- `port` - Port scanning
- `web` - Web application scanning
- `service` - Service enumeration
- `vuln` - Vulnerability scanning
- `net` - Network discovery
- `dns` - DNS enumeration
- `brute` - Brute force attacks
- `full` - Full scan (all modules except exploitation)

Run `scan.bat help` or `./scan.sh help` to see usage information.

### Advanced Usage

For more control over the scanning process, you can use the full command syntax:

```bash
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t [target] [options]
```

Examples:
```bash
# Basic port scan
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t 192.168.1.1 -p

# Full vulnerability scan
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t example.com -f

# Web application scan
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t https://example.com -w

# Network discovery
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t 192.168.1.0/24 -d

# Service enumeration only
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t 192.168.1.1 -s

# Generate detailed report
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar -t 192.168.1.1 -f -r
```

### Command-line options

```
-t, --target TARGET        Target to scan (IP, hostname, or IP range)
-p, --port-scan            Perform port scanning
-s, --service-enum         Perform service enumeration
-w, --web-scan             Perform web application scanning
-v, --vuln-scan            Perform vulnerability scanning
-d, --discover             Perform network discovery
-b, --brute-force          Perform brute force attacks
    --dns-enum             Perform DNS enumeration
    --ssl-analyze          Perform SSL/TLS analysis
-f, --full-scan            Perform full scan (all modules except exploitation)
-e, --exploit              Enable exploitation modules (use with caution)
-r, --report               Generate reports
    --report-dir DIR       Directory to store reports
-c, --config FILE          Path to configuration file
    --verbose              Enable verbose output
    --debug                Enable debug output
-h, --help                 Display help message
    --version              Display version information
```

## Configuration

Edit the `src/main/resources/config.yml` file to customize scan parameters, timeouts, and other settings.

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

This tool leverages several excellent open-source projects and libraries. 