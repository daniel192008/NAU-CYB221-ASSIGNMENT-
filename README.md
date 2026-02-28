# NAU-CYB 221 - Cybersecurity Technology Assignment

**Student Name:** Emeka Daniel Chimuanya  
**Reg No:** 2024924010  
**Department:** Cyber Security  
**Level:** 200  

## Project: Local Port Discovery Tool
[span_0](start_span)[span_1](start_span)[span_2](start_span)This program enumerates open TCP/UDP ports, identifies PIDs, and assesses exposure risk[span_0](end_span)[span_1](end_span)[span_2](end_span).

# Python Port‑scanner (`main.py`)

## What it does

`main.py` is a small Python script that walks the local network
stack (using **psutil**) and lists all *listening* TCP and UDP sockets.
For each entry it shows:

* Protocol (TCP/UDP)  
* IP address and port  
* A best‑guess service name (common ports only)  
* Exposure level (Localhost, Private, All Interfaces, Public)  
* Owning PID and, unless `--no-resolve` is given, the process name

Output is a simple fixed‑width table with a header and a separator
line.

## Requirements

* Windows, Linux or macOS – anything supported by `psutil`.  
* Python 3.6+  
* `psutil` package:  
  ```bash
  python -m pip install psutil


### How to Run
1. Install requirements: `pip install psutil`
2. [span_3](start_span)Run script: `python port_scanner.py` (Note: admin/sudo may be required for PID names[span_3](end_span)).
