# Port-Scanner
A python port scanner with open, closed, and filtered port detection, banner grabbing, JSON outputs, using threaded scanning with a summary table. Note: This tool is intended for educational purposes and testing on networks you own or have permission to scan. Unauthorized scanning of external networks may be illegal.

## Features

- Scan common port categories:  
  - Web (HTTP, HTTPS, etc.)  
  - Database (MySQL, PostgreSQL, MSSQL)  
  - Email (SMTP, POP3, IMAP)  
  - Admin/Other (SSH, RDP, VNC)  
- Detect **Open**, **Closed**, and **Filtered** ports  
- **Banner grabbing** for open ports  
- Color-coded **scan summary table**  
- Save results as **JSON**  
- Multi-threaded scanning for **speed**

## Requirements (if you want the summary table, which is useful)

- Python 3.8+  
- [colorama](https://pypi.org/project/colorama/)  
- [tabulate](https://pypi.org/project/tabulate/)  

Install dependencies:

```bash
pip install colorama tabulate
```


## Usage

run the scanner:

python portscan.py <target_ip_or_hostname>

You will be prompted with preset ranges of ports to scan, choose from a category.
if you wish to do a custom range, input a custom range into the fields.



## Example output
Start port: 1
End port: 1000
Target (ip or hostname): <your target>
Scanning ports 1-1000
Scanned 50/1000 ports...
Scanned 100/1000 ports...
...
Scanned 1000/1000 ports...

Scan complete in 2.10s

Scan Summary:
| Ports       | Status   |
|------------|---------|
| 631        | Open    |
| 1-630      | Closed  |
| 632-1000   | Closed  |


Totals: Open=1, Closed=999, Filtered=0
Saved results -> scans/scan_<target>_2025.json


## DISCLAIMER

This tool is for educational purposes only. Do not scan networks or devices without explicit permission. Unauthorized scanning may be illegal.
