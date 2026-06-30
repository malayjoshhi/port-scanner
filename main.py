import argparse
import sys
import json
import time
from scanner import PortScanner

# ANSI Terminal Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

BANNER = f"""{CYAN}
  ___ ___  ___ _____   ___  ___   _   _  _ _  _ ___ ___ 
 | _ \\ _ \\/ __|_   _| / __|/ __| /_\\ | \\| | \\| | __| _ \\
 |  _/ _ \\ (__  | |   \\__ \\ (__ / _ \\| .` | .` | _||   /
 |_| \\___/\\___| |_|   |___/\\___/_/ \\_\\_|_|\\_|_|\\_|_|___|_|_\\
{RESET}          Fast Multi-Threaded TCP Port Scanner v1.0
"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Multi-threaded TCP Port Scanner & Service Detector")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("-sp", "--start-port", type=int, default=1, help="Start port (Default: 1)")
    parser.add_argument("-ep", "--end-port", type=int, default=1024, help="End port (Default: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (Default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket connection timeout in seconds (Default: 1.0)")
    parser.add_argument("--no-banner", action="store_true", help="Disable service banner grabbing")
    parser.add_argument("-o", "--output", help="Save scan results to JSON file")

    args = parser.parse_args()

    try:
        scanner = PortScanner(args.target, timeout=args.timeout, grab_banner=not args.no_banner)
        print(f"[*] Target Host: {YELLOW}{args.target}{RESET} ({scanner.target_ip})")
        print(f"[*] Port Range : {args.start_port} - {args.end_port}")
        print(f"[*] Threads    : {args.threads}")
        print(f"[*] Scanning in progress...\n")

        start_time = time.time()
        results = scanner.scan_range(args.start_port, args.end_port, threads=args.threads)
        elapsed_time = time.time() - start_time

        print(f"\n{GREEN}{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'BANNER'}{RESET}")
        print("-" * 60)
        
        for res in results:
            port_str = f"{res['port']}/tcp"
            banner_str = res['banner'][:30] + "..." if len(res['banner']) > 30 else res['banner']
            print(f"{GREEN}{port_str:<10}{res['status']:<10}{res['service']:<15}{banner_str}{RESET}")

        print("-" * 60)
        print(f"[*] Scan completed in {YELLOW}{elapsed_time:.2f}{RESET} seconds.")
        print(f"[*] Total open ports found: {GREEN}{len(results)}{RESET}")

        if args.output:
            with open(args.output, "w") as f:
                json.dump({"target": args.target, "ip": scanner.target_ip, "results": results}, f, indent=4)
            print(f"[+] Results saved to {CYAN}{args.output}{RESET}")

    except ValueError as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan cancelled by user.{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
