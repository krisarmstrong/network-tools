
# TCP Ping Monitor with Trend Tracking

## Overview
This Python script monitors the TCP response time (ping) of a list of IP/DNS addresses using either 
a Python-based implementation or the third-party `tcping` tool. It tracks and trends the average response 
times over time, logging the data for later analysis.

## Features
- Tracks TCP response time (ping) using either Python sockets or `tcping`.
- Logs response times and tracks the running average over a customizable period.
- Supports command-line options for method and interval control.
- Logs results to a CSV file for analysis.

## Requirements
- Python 3.6 or higher.
- `tcping` (optional, if using the third-party method).
- Install required Python libraries by running:
  ```bash
  pip install -r requirements.txt
  ```

## Usage
### Command-line Options:
```bash
tcping_monitor.py [--method python|tcping] [--interval seconds]
```

- `--method`: Choose between `python` (default) or `tcping` to perform the TCP ping.
- `--interval`: Set the time interval between checks, in seconds (default: 600 seconds).

### Example:
- Using Python implementation with a 10-minute interval:
  ```bash
  python3 tcping_monitor.py --method python --interval 600
  ```

- Using third-party `tcping` tool with a 5-minute interval:
  ```bash
  python3 tcping_monitor.py --method tcping --interval 300
  ```

## License
This project is licensed under the MIT License.
