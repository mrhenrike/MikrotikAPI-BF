#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Mikrotik Network Discovery Tool

Standalone script to discover Mikrotik devices on the network
"""

import argparse
import sys
from _discovery import MikrotikDiscovery
from _log import Log

def main():
    parser = argparse.ArgumentParser(
        description="Discover Mikrotik devices on the network",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Network scanning options
    network_group = parser.add_mutually_exclusive_group(required=True)
    network_group.add_argument(
        "-n", "--network",
        help="Network in CIDR notation (e.g., 192.168.1.0/24)"
    )
    network_group.add_argument(
        "-r", "--range",
        nargs=2,
        metavar=("START_IP", "END_IP"),
        help="IP range to scan (e.g., 192.168.1.1 192.168.1.254)"
    )
    network_group.add_argument(
        "-t", "--target",
        help="Single target IP to scan"
    )
    
    # Performance options
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="Connection timeout in seconds (default: 2)"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        help="Export results to JSON file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Initialize discovery
    discovery = MikrotikDiscovery(
        timeout=args.timeout,
        threads=args.threads
    )
    
    log = Log(verbose=args.verbose, verbose_all=False)
    
    try:
        # Perform scan
        if args.network:
            log.info(f"Scanning network: {args.network}")
            results = discovery.scan_network(args.network)
            
        elif args.range:
            start_ip, end_ip = args.range
            log.info(f"Scanning range: {start_ip} to {end_ip}")
            results = discovery.scan_range(start_ip, end_ip)
            
        elif args.target:
            log.info(f"Scanning target: {args.target}")
            result = discovery.scan_host(args.target)
            results = [result] if result else []
        
        # Display results
        print(f"\n{'='*60}")
        print(f"DISCOVERY RESULTS")
        print(f"{'='*60}\n")
        
        if results:
            for idx, device in enumerate(results, 1):
                print(f"[{idx}] {device['ip']}")
                print(f"    Likely Mikrotik: {'YES' if device['likely_mikrotik'] else 'MAYBE'}")
                print(f"    Open ports:")
                for service, port in device['ports'].items():
                    print(f"      - {service}: {port}")
                print()
            
            print(f"Total devices found: {len(results)}")
        else:
            print("No Mikrotik devices found.")
        
        # Export if requested
        if args.output:
            filename = discovery.export_results(args.output)
            log.info(f"Results exported to: {filename}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

