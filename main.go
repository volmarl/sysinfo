package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// reportHeader is the main title for the generated report.
	reportHeader = "System Diagnostic Report"
	// analysisHeader is the title for the special analysis sections.
	analysisHeader = ">>> Automated Analysis"
	// RHEL_DEPS lists dependencies for RHEL-based systems.
	RHEL_DEPS = "For RHEL/CentOS/Fedora, please ensure these packages are installed: \n'sudo yum install -y procps-ng iproute net-tools lsof sysstat hdparm lshw dmidecode ethtool util-linux'"
	// DEBIAN_DEPS lists dependencies for Debian-based systems.
	DEBIAN_DEPS = "For Debian/Ubuntu, please ensure these packages are installed: \n'sudo apt-get install -y procps iproute2 net-tools lsof sysstat hdparm lshw dmidecode ethtool util-linux'"
	// HELP_MESSAGE combines all help information.
	HELP_MESSAGE = `
Go System Diagnostic Collector
--------------------------------
This tool collects a wide range of system diagnostics and saves them to a report file.
It requires sudo privileges to run, as it needs to access system-level information.

Usage:
  sudo ./sys-diag-collector [options]

Options:
  -o, --output <filename>   Specify the output report file name (default: "diagnostic_report_YYYY-MM-DD_HHMMSS.txt")
  -h, --help                Show this help message

Dependencies:
` + RHEL_DEPS + `
` + DEBIAN_DEPS + `
`
)

// Command holds the shell command to be executed and its description.
type Command struct {
	Description string
	Cmd         string
}

// getCommands returns a list of all diagnostic commands to be executed.
func getCommands() []Command {
	// Note: Some commands use complex shell pipelines. We run them via `sh -c "..."`
	return []Command{
		{"System Hostname and IP", `hostname -I`},
		{"Kernel and OS Info", `uname -a`},
		{"Linux Standard Base Release Info", `lsb_release -a`},
		{"System Hardware Summary", `lshw -class system`},
		{"Virtualization Detection", `systemd-detect-virt`},
		{"DMI Product Name", `dmidecode -s system-product-name`},
		{"DMI Product Name (Alternative)", `cat /sys/class/dmi/id/product_name`},
		{"DMI System Vendor", `cat /sys/class/dmi/id/sys_vendor`},
		{"System Uptime", `uptime`},
		{"Kernel Messages (Timestamps)", `dmesg -T`},
		{"CPU Information", `lscpu`},
		{"Detailed CPU Information", `cat /proc/cpuinfo`},
		{"Process Snapshot (Top)", `top -n3 -b`},
		{"Memory Info", `cat /proc/meminfo`},
		{"Memory Usage (MB)", `free -m`},
		{"Mounted Filesystems", `mount`},
		{"Filesystem Disk Usage", `df -h`},
		{"Block Devices", `lsblk`},
		{"Disk Partitions", `cat /proc/partitions`},
		{"Disk Model Information", `ls /sys/block/{sd*,xvd*,nvme*}/device/model 2>/dev/null | xargs -I f sh -c "echo f; cat f;"`},
		{"Disk Rotational Status (1=HDD, 0=SSD)", `ls /sys/block/{sd*,xvd*,nvme*}/queue/rotational 2>/dev/null | xargs -I f sh -c "echo f; cat f;"`},
		{"Disk I/O Scheduler", `ls /sys/block/{sd*,xvd*,nvme*}/queue/scheduler 2>/dev/null | xargs -I f sh -c "echo f; cat f;"`},
		{"Disk Controller Info (hdparm)", `fdisk -l | grep Disk | grep /dev | cut -d " " -f 2 | cut -d ":" -f 1 | xargs hdparm -I 2>/dev/null`},
		{"I/O Statistics (4 samples, 5s interval)", `iostat -y -x 5 4`},
		{"CPU Statistics (3 samples, 2s interval)", `mpstat -P ALL 2 3`},
		{"System Interrupts", `cat /proc/interrupts`},
		{"Network Interfaces (IP Addr)", `ip addr`},
		{"Network Link Statistics", `ip -s link`},
		{"Network Interfaces (Legacy)", `netstat -i | tr -s '[:blank:]' | cut -d" " -f1 | tail -n +3 | grep -v -E "lo|docker" | xargs --max-lines=1 -i{} sh -c "echo 'ethtool -S {}'; ethtool -S {}"`},
		{"Network Connections (netstat)", `netstat -n`},
		{"ARP Table", `arp -n`},
		{"ARP Cache Garbage Collection Thresholds", `find /proc/sys/net/ipv4/neigh/default/ -name "gc_thresh*" -print -exec cat {} \;`},
		{"IP Tables (Firewall Rules)", `iptables -L -vn`},
		{"Network Device Statistics (sar)", `sar -n DEV 1 3`},
		{"Network Device Error Statistics (sar)", `sar -n EDEV 1 3`},
		{"Count TIME_WAIT connections on port 3000", `ss -ant state time-wait sport = :3000 or dport = :3000 | wc -l`},
		{"Count CLOSE_WAIT connections on port 3000", `ss -ant state close-wait sport = :3000 or dport = :3000 | wc -l`},
		{"Count ESTABLISHED connections on port 3000", `ss -ant state established sport = :3000 or dport = :3000 | wc -l`},
		{"Count LISTEN connections on port 3000", `ss -ant state listen sport = :3000 or dport = :3000 | wc -l`},
		{"Kernel Shared Memory / File Limits", `sysctl -a 2>/dev/null | grep -E "shmmax|file-max|maxfiles"`},
		{"Kernel Minimum Free Kilobytes", `sysctl vm.min_free_kbytes`},
		{"Transparent Hugepage Status (Enabled)", `cat /sys/kernel/mm/*transparent_hugepage/enabled`},
		{"Transparent Hugepage Status (Defrag)", `cat /sys/kernel/mm/*transparent_hugepage/defrag`},
		{"Transparent Hugepage Status (khugepaged Defrag)", `cat /sys/kernel/mm/*transparent_hugepage/khugepaged/defrag`},
		{"Process Limits for 'asd'", `pgrep asd | xargs -I f sh -c "cat /proc/f/limits"`},
		{"Memory Usage for 'asd' processes", `ps -eo rss,vsz,comm | grep asd`},
		{"Installed 'citrus' or 'aero' RPMs", `rpm -qa | grep -E "citrus|aero"`},
		{"Open Files (lsof)", `lsof`},
		{"Environment Variables", `env`},
	}
}


// analyzeTop checks for high CPU or memory usage in top's output.
// This version is robustly designed to handle multiple snapshots from `top -n3 -b`
// and correctly parse lines even when command names contain spaces.
func analyzeTop(output string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("\n%s\n", analysisHeader))

	lines := strings.Split(output, "\n")
	cpuIndex, memIndex, cmdIndex := -1, -1, -1
	highUsageFound := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue // Skip empty lines
		}

		// Check if the current line is a header line. This resets indices for each new snapshot.
		if strings.Contains(trimmedLine, "PID") && strings.Contains(trimmedLine, "%CPU") && strings.Contains(trimmedLine, "COMMAND") {
			fields := strings.Fields(trimmedLine)
			cpuIndex, memIndex = -1, -1
			for i, field := range fields {
				if field == "%CPU" {
					cpuIndex = i
				}
				if field == "%MEM" {
					memIndex = i
				}
				// The COMMAND column is always last in the header.
				if field == "COMMAND" {
					cmdIndex = i
				}
			}
			continue // Skip to the next line after processing the header
		}

		// A valid process line must start with a digit (the PID).
		// We also must have successfully found the header column indices.
		isProcessLine, _ := regexp.MatchString(`^\d`, trimmedLine)
		if !isProcessLine || cpuIndex == -1 || memIndex == -1 {
			continue
		}

		fields := strings.Fields(trimmedLine)
		// Ensure the line has enough columns to parse.
		if len(fields) > cpuIndex && len(fields) > memIndex {
			cpuUsage, errCPU := strconv.ParseFloat(fields[cpuIndex], 64)
			memUsage, errMEM := strconv.ParseFloat(fields[memIndex], 64)
			
			// Reconstruct the command name, which might contain spaces.
			// The command starts at the cmdIndex, which we found from the header.
			var commandName string
			if cmdIndex != -1 && len(fields) > cmdIndex {
				commandName = strings.Join(fields[cmdIndex:], " ")
			} else {
				// Fallback if COMMAND column isn't found, though unlikely.
				commandName = "N/A"
			}


			if errCPU == nil && cpuUsage > 80.0 {
				analysis.WriteString(fmt.Sprintf("  - [WARNING] High CPU Usage Detected: Process '%s' (PID %s) is using %.2f%% CPU.\n", commandName, fields[0], cpuUsage))
				highUsageFound = true
			}
			if errMEM == nil && memUsage > 50.0 {
				analysis.WriteString(fmt.Sprintf("  - [WARNING] High Memory Usage Detected: Process '%s' (PID %s) is using %.2f%% Memory.\n", commandName, fields[0], memUsage))
				highUsageFound = true
			}
		}
	}

	if !highUsageFound {
		analysis.WriteString("  - No processes found with high CPU (>80%) or Memory (>50%) usage.\n")
	}

	return analysis.String()
}

// analyzeInterrupts checks for network interrupt imbalance.
func analyzeInterrupts(output string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("\n%s\n", analysisHeader))

	cpuCount := 0
	imbalanceFound := false
	lines := strings.Split(output, "\n")

	if len(lines) > 0 {
		cpuCount = len(strings.Fields(lines[0]))
	}

	// Regex to find network RX/TX queues. Adjust if you have different interface naming conventions (e.g., ib for InfiniBand).
	netInterruptRegex := regexp.MustCompile(`(eth|en[opsx]|ib)\d+.*-(rx|tx)`)

	for _, line := range lines {
		if netInterruptRegex.MatchString(line) {
			fields := strings.Fields(line)
			interrupts := []int64{}
			totalInterrupts := int64(0)
			
			// Fields between the first (IRQ number) and last (device name) are CPU counts.
			for i := 1; i < len(fields)-1 && i <= cpuCount; i++ {
				val, err := strconv.ParseInt(fields[i], 10, 64)
				if err == nil {
					interrupts = append(interrupts, val)
					totalInterrupts += val
				}
			}
			
			if len(interrupts) < 2 {
				continue // Not enough data for comparison
			}

			// Simple imbalance check: is one core handling a disproportionate number of interrupts?
			for i, count := range interrupts {
				// If a single CPU handles >75% of the interrupts and there are at least 2 CPUs, flag it.
				if totalInterrupts > 1000 && float64(count) > float64(totalInterrupts)*0.75 && len(interrupts) > 1 {
					deviceName := fields[len(fields)-1]
					analysis.WriteString(fmt.Sprintf("  - [WARNING] Potential Interrupt Imbalance on '%s': CPU%d handled %d interrupts (%.2f%% of total).\n", deviceName, i, count, (float64(count)/float64(totalInterrupts))*100))
					imbalanceFound = true
				}
			}
		}
	}

	if !imbalanceFound {
		analysis.WriteString("  - No significant RX/TX network interrupt imbalance detected across CPU cores.\n")
	}
	return analysis.String()
}

// analyzeDmesg highlights lines containing common error keywords.
func analyzeDmesg(output string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("\n%s\n", analysisHeader))
	
	errorKeywords := []string{"error", "fail", "failed", "segfault", "panic", "critical", "denied"}
	foundErrors := false
	
	for _, line := range strings.Split(output, "\n") {
		lowerLine := strings.ToLower(line)
		for _, keyword := range errorKeywords {
			if strings.Contains(lowerLine, keyword) {
				analysis.WriteString(fmt.Sprintf("  - [ALERT] Found potential error keyword '%s': %s\n", keyword, line))
				foundErrors = true
				break // Move to next line after first keyword match
			}
		}
	}

	if !foundErrors {
		analysis.WriteString("  - No lines containing common error keywords (error, fail, panic, etc.) found in dmesg output.\n")
	}
	return analysis.String()
}

// analyzeIpAddr counts and lists network interfaces.
func analyzeIpAddr(output string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("\n%s\n", analysisHeader))

	// Regex to find interface lines like "1: lo:", "2: eth0:"
	interfaceRegex := regexp.MustCompile(`(?m)^[0-9]+:\s+([\w.-]+):`)
	matches := interfaceRegex.FindAllStringSubmatch(output, -1)
	
	if len(matches) > 0 {
		var interfaceNames []string
		for _, match := range matches {
			interfaceNames = append(interfaceNames, match[1])
		}
		analysis.WriteString(fmt.Sprintf("  - Found %d network interface(s): %s\n", len(interfaceNames), strings.Join(interfaceNames, ", ")))
	} else {
		analysis.WriteString("  - No network interfaces found.\n")
	}
	return analysis.String()
}

// analyzeSarDev checks for spikes in network traffic.
func analyzeSarDev(output string) string {
	var analysis strings.Builder
	analysis.WriteString(fmt.Sprintf("\n%s\n", analysisHeader))

	lines := strings.Split(output, "\n")
	rxIndex, txIndex := -1, -1
	spikeFound := false

	for _, line := range lines {
		// Find header to locate columns
		if strings.Contains(line, "IFACE") && strings.Contains(line, "rxkB/s") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "rxkB/s" {
					rxIndex = i
				}
				if field == "txkB/s" {
					txIndex = i
				}
			}
			continue
		}

		if rxIndex == -1 || txIndex == -1 || !strings.Contains(line, "Average:") {
			continue // Process only data lines after header
		}
		
		fields := strings.Fields(line)
		if len(fields) > rxIndex && len(fields) > txIndex {
			iface := fields[1]
			rxKB, errRX := strconv.ParseFloat(fields[rxIndex], 64)
			txKB, errTX := strconv.ParseFloat(fields[txIndex], 64)
			
			// Define a "spike" as > 100 MB/s (102400 kB/s). This is an arbitrary threshold.
			const spikeThreshold = 102400.0

			if errRX == nil && rxKB > spikeThreshold {
				analysis.WriteString(fmt.Sprintf("  - [INFO] High bandwidth usage detected on interface '%s': Average received data is %.2f kB/s.\n", iface, rxKB))
				spikeFound = true
			}
			if errTX == nil && txKB > spikeThreshold {
				analysis.WriteString(fmt.Sprintf("  - [INFO] High bandwidth usage detected on interface '%s': Average transmitted data is %.2f kB/s.\n", iface, txKB))
				spikeFound = true
			}
		}
	}
	
	if !spikeFound {
		analysis.WriteString("  - No significant bandwidth spikes (>100MB/s) detected in the sampled period.\n")
	}

	return analysis.String()
}


// executeAndWrite runs a command and writes its output and any special analysis to the writer.
func executeAndWrite(writer *bufio.Writer, cmd Command) {
	header := fmt.Sprintf("\n\n================================================================================\n# %s\n# CMD: %s\n================================================================================\n\n", cmd.Description, cmd.Cmd)
	writer.WriteString(header)

	// Execute command using "sh -c" to handle pipes and complex syntax
	out, err := exec.Command("sh", "-c", cmd.Cmd).CombinedOutput()
	if err != nil {
		writer.WriteString(fmt.Sprintf("Error executing command: %v\n", err))
	}
	writer.Write(out)

	// Perform special analysis for specific commands
	switch cmd.Cmd {
	case "top -n3 -b":
		writer.WriteString(analyzeTop(string(out)))
	case "cat /proc/interrupts":
		writer.WriteString(analyzeInterrupts(string(out)))
	case "dmesg -T":
		writer.WriteString(analyzeDmesg(string(out)))
	case "ip addr":
		writer.WriteString(analyzeIpAddr(string(out)))
	case "sar -n DEV 1 3": // Match the sar command we use
		writer.WriteString(analyzeSarDev(string(out)))
	}
}

func main() {
	// Check for root privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run with sudo or as the root user.")
	}
	
	// Define command-line flags
	outputFileName := flag.String("o", "", "Output report file name")
	showHelp := flag.Bool("h", false, "Show help message")
	flag.BoolVar(showHelp, "help", false, "Show help message")
	flag.Parse()

	if *showHelp {
		fmt.Println(HELP_MESSAGE)
		os.Exit(0)
	}

	// Set default filename if not provided
	if *outputFileName == "" {
		timestamp := time.Now().Format("2006-01-02_150405")
		*outputFileName = fmt.Sprintf("diagnostic_report_%s.txt", timestamp)
	}
	
	// Create and open the report file
	file, err := os.Create(*outputFileName)
	if err != nil {
		log.Fatalf("Failed to create report file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write report header
	writer.WriteString(fmt.Sprintf("%s\n", reportHeader))
	writer.WriteString(fmt.Sprintf("Generated on: %s\n", time.Now().Format(time.RFC1123)))

	// Execute all commands
	commands := getCommands()
	fmt.Printf("Starting diagnostic capture... Report will be saved to %s\n", *outputFileName)
	for i, cmd := range commands {
		fmt.Printf("Running command %d/%d: %s\n", i+1, len(commands), cmd.Description)
		executeAndWrite(writer, cmd)
	}

	fmt.Println("Diagnostic report successfully generated.")
}
