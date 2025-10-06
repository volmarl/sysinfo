# Go System Diagnostic Collector

A simple, powerful command-line tool written in Go to capture a comprehensive set of system diagnostics on a Linux machine. It is designed to be run with `sudo` to gather detailed hardware, software, network, and performance data, which it then saves into a single, human-readable text file.

The tool also performs basic automated analysis on the output of several critical commands to help you quickly identify potential issues.

## Features

-   **Comprehensive Data Collection**: Gathers information from over 40 standard Linux commands.
-   **Automated Analysis**: Provides quick insights on:
    -   High CPU or Memory usage from `top`.
    -   Network interrupt (RXTX) imbalance on CPU cores.
    -   Potential hardware/system errors in `dmesg`.
    -   Summary of network interfaces.
    -   Spikes in network bandwidth usage from `sar`.
-   **Single File Output**: Consolidates all information into one easy-to-share text report.
-   **Portable**: Compiled into a single binary with no runtime dependencies other than the system commands it calls.
-   **User-Friendly**: Simple command-line flags for specifying an output file or showing help.

## Prerequisites

### 1. Go Compiler

You need a Go compiler (version 1.18 or newer is recommended) installed on your machine to build the program.

### 2. Sudo / Root Access

The program must be run with `sudo` because many of the diagnostic commands require elevated privileges to access kernel and hardware information.

### 3. Package Dependencies

This tool is a wrapper around common Linux command-line utilities. You must ensure they are installed on the system where you intend to run the collector.

-   **For RHEL-based systems (CentOS, Fedora, Rocky Linux):**
    ```sh
    sudo yum install -y procps-ng iproute net-tools lsof sysstat hdparm lshw dmidecode ethtool util-linux
    ```

-   **For Debian-based systems (Ubuntu):**
    ```sh
    sudo apt-get update
    sudo apt-get install -y procps iproute2 net-tools lsof sysstat hdparm lshw dmidecode ethtool util-linux
    ```

## Compilation

1.  Save the code above into a file named `main.go`.
2.  Open your terminal and navigate to the directory where you saved the file.
3.  Run the following command to build the binary:

    ```sh
    go build -o sys-diag-collector main.go
    ```

    This will create an executable file named `sys-diag-collector` in the same directory.

## Usage

Once compiled, you can run the tool from your terminal.

-   **Run with default options:**

    This will create a report file with a timestamp in the name (e.g., `diagnostic_report_2025-10-06_085037.txt`).

    ```sh
    sudo ./sys-diag-collector
    ```

-   **Specify a custom output file name:**

    Use the `-o` or `--output` flag to name your report file.

    ```sh
    sudo ./sys-diag-collector -o my_server_report.txt
    ```

-   **Show the help message:**

    To see the usage information and dependency list, use the `-h` or `--help` flag.

    ```sh
    ./sys-diag-collector -h
    ```

## Report Structure

The generated text file is structured for readability. Each command's output is separated by a clear header that includes a description and the exact command that was run.

For commands with automated analysis, a special `>>> Automated Analysis` section will appear directly below the command's raw output, highlighting any noteworthy findings.

**Example Snippet from a Report:**
