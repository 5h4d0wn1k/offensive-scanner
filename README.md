> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# Offensive Scanner

Modular Java penetration-testing scanner: port scanning, service enumeration,
banner grabbing, OS detection, web and SSL/TLS analysis, DNS enumeration, and
HTML/PDF reporting — for authorized **penetration testing** labs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/offensive-scanner)](https://github.com/5h4d0wn1k/offensive-scanner)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/offensive-scanner)](https://github.com/5h4d0wn1k/offensive-scanner/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/offensive-scanner)](https://github.com/5h4d0wn1k/offensive-scanner)

## Why

Solid reconnaissance is the foundation of any professional penetration test: an
accurate inventory of open ports, running services, web layers, and SSL/TLS
weaknesses tells you where to focus — and gives the client the evidence trail
they need for remediation. Offensive Scanner packages that reconnaissance into
a single Java 11+ CLI with a clean module system — port, service, web,
vulnerability, network, DNS, SSL/TLS, and brute-force modules — plus HTML and
PDF report generation from scanned results. It is designed around authorized,
scoped engagements: every module is opt-in, reports are explicit, and the
timing/concurrency parameters live in a single config file. The scanner is only
a legitimate instrument when pointed at systems you own or hold written
authorization to assess.

## Features

- **Port scanning** — TCP port discovery and service fingerprinting
- **Service enumeration** — version-level service detection
- **Banner grabbing** — identify software and versions
- **Network discovery** — map topology and enumerate hosts
- **OS detection** — inference of target operating systems
- **Web application scanning** — common web vulnerability checks
- **SSL/TLS analysis** — weak ciphers and certificate issues
- **DNS enumeration** — domain and subdomain discovery
- **Brute-force module** — password testing against common services
- **Exploitation modules** — opt-in scripts behind the `-e` flag
- **Reporting** — HTML and PDF reports + H2 result database

## Quickstart

Requirements: Java 11+, Maven.

```bash
# Build (produces both jars in target/)
mvn clean package

# Linux/macOS helper script
chmod +x scan.sh
./scan.sh 192.168.1.1 port
./scan.sh example.com web report

# Windows helper script
scan.bat 192.168.1.1 port

# Advanced usage
java -jar target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar \
  -t 192.168.1.1 -f -r
```

Scan types (`scan.sh`/`scan.bat`): `port`, `web`, `service`, `vuln`, `net`,
`dns`, `brute`, `full` — use `help` to print usage.

Key CLI flags: `-t/--target`, `-p/--port-scan`, `-s/--service-enum`,
`-w/--web-scan`, `-v/--vuln-scan`, `-d/--discover`, `-b/--brute-force`,
`--dns-enum`, `--ssl-analyze`, `-f/--full-scan`, `-e/--exploit`,
`-r/--report`, `-c/--config`.

## Configuration

Edit `config.yml` (top level, copied into `src/main/resources/`) to customize
scan parameters, timeouts, and threading. Uses `src/main/resources/wordlists`
for dictionary-based modules.

## Project structure

- `src/main/java/com/offensivescanner/` — core (`OffensiveScanner`, `ScanManager`,
  `ConfigManager`, `ScanResults`) and `modules/`
  (`PortScanner`, `ServiceEnumerator`, `WebScanner`, `VulnerabilityScanner`,
  `NetworkScanner`, `DNSScanner`, `SSLScanner`, `BruteForceScanner`,
  `ExploitScanner`)
- `config.yml` — scan configuration
- `scan.sh` / `scan.bat` — simplified command wrappers
- `wordlists/` — default dictionaries

## Legal & authorized use

For **educational and authorized security testing purposes only**. Unauthorized
scanning of systems you do not own or lack written permission to test is illegal
in most jurisdictions. See [ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md), and
[SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).