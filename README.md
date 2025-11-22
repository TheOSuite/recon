# recon

[![GitHub stars](https://img.shields.io/github/stars/TheOSuite/recon?style=social)](https://github.com/TheOSuite/recon)
[![GitHub forks](https://img.shields.io/github/forks/TheOSuite/recon?style=social)](https://github.com/TheOSuite/recon)
[![GitHub issues](https://img.shields.io/github/issues/TheOSuite/recon)](https://github.com/TheOSuite/recon/issues)
[![GitHub license](https://img.shields.io/github/license/TheOSuite/recon)](https://github.com/TheOSuite/recon/blob/main/LICENSE)

**recon** is a powerful, shell-based subdomain enumeration tool designed specifically for Android Termux environments (with full compatibility in Kali Linux and other Linux distributions). It performs aggressive subdomain discovery using a variety of techniques, including wordlist-based brute-forcing, permutation generation, and integration with external resolvers. Whether you're conducting authorized penetration testing or security research, recon streamlines the process of mapping out a target's attack surface.

This tool is lightweight, fast, and highly customizable, making it an essential addition to any reconnaissance toolkit.

## Features

- **Aggressive Subdomain Enumeration**: Discovers thousands of subdomains using multiple sources and techniques.
- **Customizable Host Limits**: Specify the number of hosts to process (e.g., save more or fewer results for efficiency).
- **Full Scan Mode**: Enables comprehensive scanning, including port enumeration and service detection (`--full` flag).
- **Port Skipping**: Option to bypass port scanning for quicker runs (`--skip-ports` flag).
- **Stealth Mode**: Integrates with Tor for anonymous operations (`--stealth` flag) – ideal for evading detection.
- **Automated Output Management**: Results are automatically saved to organized folders, including lists of live hosts, open ports, and screenshots (if applicable).
- **Cross-Platform**: Optimized for Termux on Android but runs seamlessly on Linux desktops.

## Prerequisites

- **Android Termux**: Install from F-Droid or Google Play. Update packages with `pkg update && pkg upgrade`.
- **Linux (e.g., Kali)**: Ensure bash and common utilities are available.
- **Dependencies**:
  - `tor`: For stealth mode.
  - Optional: `curl`, `wget`, `dnsrecon`, `sublist3r`, `amass` (auto-installed if missing in supported environments).

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/TheOSuite/recon.git
   ```

2. Navigate to the directory:
   ```
   cd recon
   ```

3. Make the script executable:
   ```
   chmod +x recon.sh
   ```

4. Install Tor (required for stealth mode):
   - In Termux: `pkg install tor`
   - In Kali/Debian: `apt-get install tor`
   - Alternatively, via pip: `pip install tor`

5. (Optional) Install additional tools for enhanced functionality:
   ```
   pkg install curl wget dnsutils  # Termux
   # or
   apt-get install curl wget dnsutils  # Kali
   ```

## Usage

Run the script with a target domain as the first argument. Optional parameters allow customization.

### Basic Syntax
```
./recon.sh <domain> [host_limit] [flags]
```

- `<domain>`: The target domain (e.g., `example.com`).
- `[host_limit]`: Number of subdomains to process/save (default: 100).
- `[flags]`: Optional modifiers (see below).

### Examples

1. **Basic Subdomain Enumeration**:
   ```
   ./recon.sh example.com
   ```
   Performs standard enumeration and saves results to `./output/example.com/`.

2. **Enumerate and Save More Hosts**:
   ```
   ./recon.sh example.com 500
   ```
   Processes up to 500 subdomains for deeper discovery.

3. **Full Scan (Includes Port Scanning)**:
   ```
   ./recon.sh example.com 300 --full
   ```
   Runs complete reconnaissance, including open port detection.

4. **Skip Port Scanning** (Faster Run):
   ```
   ./recon.sh example.com 200 --skip-ports
   ```
   Focuses solely on subdomain discovery without service probing.

5. **Stealth Mode** (With Tor):
   ```
   tor &  # Start Tor in the background
   ./recon.sh example.com --stealth
   ```
   Routes all requests through Tor for anonymity. Ensure Tor is configured and running.

### Output
- Results are saved in `./output/<domain>/`:
  - `live_hosts.txt`: Resolved, live subdomains.
  - `ports.txt`: Open ports and services (if scanned).
  - `all_subdomains.txt`: Complete list of discovered subdomains.
- Logs are verbose by default; use `--quiet` for minimal output (future enhancement).

## Flags Overview

| Flag          | Description                          | Example                  |
|---------------|--------------------------------------|--------------------------|
| `--full`     | Enable full scan (ports + services) | `./recon.sh domain.com --full` |
| `--skip-ports` | Skip port enumeration              | `./recon.sh domain.com --skip-ports` |
| `--stealth`  | Use Tor for anonymous requests     | `./recon.sh domain.com --stealth` |
| `--help`     | Show usage help                    | `./recon.sh --help`     |

## Ethical Usage
- **Only use recon on domains you own or have explicit written permission to test.** Unauthorized scanning may violate laws like the Computer Fraud and Abuse Act (CFAA) or equivalent in your jurisdiction.
- This tool is for educational and authorized security testing purposes only.

## Contributing
Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

We appreciate bug reports, feature suggestions, and pull requests. Check out our [issues page](https://github.com/TheOSuite/recon/issues) to get started.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support
- Found a bug? [Open an issue](https://github.com/TheOSuite/recon/issues/new).
- Questions? Join the discussion in the issues or reach out via the repository maintainer.
- Star the repo if it helps your workflow! ⭐

## Changelog
- **v1.0.0** (Initial Release): Core enumeration, Tor integration, and basic flags.
- Future: Add support for custom wordlists, API integrations (e.g., Chaos DB), and GUI wrapper for Termux.

---

*Built with ❤️ by TheOSuite. Last updated: November 2025.*
