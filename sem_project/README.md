# CUPS IPP Exploit Chain & Detection (CVE-2024-47176, CVE-2024-47076, CVE-2024-47175)

**Author:** Jarrett Minot
**Course:** ITIS6200


## Project Overview
This project demonstrates a full attack chain against the Common UNIX Printing System (CUPS) architecture, specifically targeting the `cups-browsed` daemon and local `cupsd` attribute sanitization failures. The attack leverages spoofed UDP broadcasts to force a TCP callback, delivering a malicious IPP 2.0 dictionary that escapes PPD formatting to achieve code execution via Foomatic filters. 


## Environment Setup

### 1. The Target (Victim Print Server)
* **Hardware:** Raspberry Pi 5
* **OS:** Debian 12 (Bookworm)
* **Required Vulnerable Packages:**
  To successfully emulate the vulnerability, the target must be downgraded to the pre-patched versions of the CUPS filtering libraries.
  ```bash
  # Downgrade packages to the vulnerable 1.28.17-3 baseline
  sudo dpkg -i cups-browsed_1.28.17-3_arm64.deb \
               libcupsfilters1_1.28.17-3_arm64.deb \
               cups-filters-core-drivers_1.28.17-3_arm64.deb
               
  # Lock the packages to prevent automatic security patching
  sudo apt-mark hold cups-browsed libcupsfilters1 cups-filters-core-drivers
  
  # Restart the vulnerable service
  sudo systemctl restart cups-browsed
  
* Monitor cups-browsed logs via: sudo journalctl -u cups-browsed -f
* Monitor local cupsd queue creation and PPD generation via: sudo tail -f /var/log/cups/error_log
  
### 2. Configure client 
* **Hardware:** M2 Macbook pro
* **OS:** Sequoia 15.7.3
* Execute and run ipp_server.py
* In another terminal execute spoofed.py (make sure pi's IP is updated) 
