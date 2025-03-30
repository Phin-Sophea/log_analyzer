This script only accepts ssh and apache log files. More information in the future.

usage: log_analyzer.py [-h] --file FILE --type {ssh,apache} [--output OUTPUT] [--format {txt,html}] [--threshold THRESHOLD] [--window WINDOW] [--ddos-threshold DDOS_THRESHOLD]

Security Log Analyzer by Sophea Phin

options:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  Path to the log file
  --type {ssh,apache}, -t {ssh,apache}
                        Type of log file
  --output OUTPUT, -o OUTPUT
                        Output file prefix for the report
  --format {txt,html}   Output format for the report
  --threshold THRESHOLD
                        Threshold for brute force detection
  --window WINDOW       Time window in minutes for brute force detection
  --ddos-threshold DDOS_THRESHOLD
                        Requests per minute threshold for DDoS detection
