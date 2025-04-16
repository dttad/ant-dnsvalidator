#!/usr/bin/env python3

import dns.resolver
import sys
import os
import signal
import random
import string
import concurrent.futures
from ipaddress import ip_address, IPv4Address, IPv6Address
from functools import lru_cache
from typing import List, Dict, Union, Optional, Set, Tuple

from .lib.core.input import InputParser, InputHelper
from .lib.core.output import OutputHelper, Level


class DNSValidator:
    """Main class for validating DNS servers against poisoning and other issues."""
    
    def __init__(self, arguments):
        self.arguments = arguments
        self.output = OutputHelper(arguments)
        self.baselines = ["1.1.1.1", "8.8.8.8"]
        self.positivebaselines = ["bet365.com", "telegram.com"]
        self.nxdomainchecks = ["facebook.com", "paypal.com", "google.com", 
                               "bet365.com", "wikileaks.com"]
        self.valid_servers: List[str] = []
        self.baseline_responses: Dict[str, Dict] = {}
        self.rootdomain = arguments.rootdomain
        self.good_ip: Optional[str] = None
        
    @staticmethod
    def generate_random_subdomain(length: int = 10) -> str:
        """Generate a random subdomain string."""
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    @staticmethod
    def is_valid_ip(ip: str) -> Union[type, bool]:
        """Check if the string is a valid IP address."""
        try:
            ip_type = type(ip_address(ip))
            if ip_type in (IPv4Address, IPv6Address):
                return ip_type
            return False
        except ValueError:
            return False
    
    def create_resolver(self, nameserver: str) -> dns.resolver.Resolver:
        """Create a configured DNS resolver for the given nameserver."""
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = 2.0  # Set a reasonable timeout
        resolver.lifetime = 4.0  # Total timeout for all queries
        return resolver
    
    @lru_cache(maxsize=128)
    def resolve_query(self, nameserver: str, query: str, record_type: str = 'A') -> Tuple[bool, Optional[str]]:
        """Resolve a DNS query and return result with caching for performance."""
        resolver = self.create_resolver(nameserver)
        try:
            answer = resolver.query(query, record_type)
            return True, str(answer[0])
        except dns.resolver.NXDOMAIN:
            return False, "NXDOMAIN"
        except dns.exception.Timeout:
            return False, "TIMEOUT"
        except Exception as e:
            return False, str(e)
    
    def check_dns_poisoning(self, server: str) -> bool:
        """Check if a DNS server shows signs of poisoning."""
        resolver = self.create_resolver(server)
        
        for domain in self.nxdomainchecks:
            random_subdomain = f"{self.generate_random_subdomain()}.{domain}"
            try:
                resolver.query(random_subdomain, 'A')
                # We got an answer when we should have received NXDOMAIN
                self.output.terminal(Level.ERROR, server, 
                                    f"DNS poisoning detected for {random_subdomain}")
                return True
            except dns.resolver.NXDOMAIN:
                # This is expected, continue testing
                continue
            except Exception:
                # Other errors may indicate server issues
                self.output.terminal(Level.ERROR, server, 
                                    "Error when checking for DNS poisoning")
                return True
        return False
    
    def validate_server(self, server: str) -> None:
        """Validate a DNS server against our criteria."""
        # Skip if not a valid IP
        if not self.is_valid_ip(server):
            self.output.terminal(Level.VERBOSE, server, "skipping as not valid IP")
            return
        
        self.output.terminal(Level.INFO, server, "Checking...")
        
        # Check for DNS poisoning first
        if self.check_dns_poisoning(server):
            return
        
        # Check for correct root domain resolution
        success, ip = self.resolve_query(server, self.rootdomain)
        if not success or ip != self.good_ip:
            self.output.terminal(Level.REJECTED, server, f"Failed to resolve {self.rootdomain} correctly")
            return
            
        # Check for proper NXDOMAIN handling
        random_subdomain = f"{self.generate_random_subdomain()}.{self.rootdomain}"
        success, result = self.resolve_query(server, random_subdomain)
        if success:  # Should have been NXDOMAIN
            self.output.terminal(Level.REJECTED, server, "Does not properly return NXDOMAIN")
            return
            
        # Server passed all checks
        self.output.terminal(Level.ACCEPTED, server, "provided valid response")
        self.valid_servers.append(server)
    
    def establish_baseline(self) -> bool:
        """Establish baseline responses from trusted DNS servers."""
        for baseline in self.baselines:
            self.output.terminal(Level.INFO, baseline, "resolving baseline")
            
            # Resolve root domain
            success, ip = self.resolve_query(baseline, self.rootdomain)
            if not success:
                self.output.terminal(Level.ERROR, baseline, 
                                    f"Failed to resolve baseline domain {self.rootdomain}")
                return False
                
            # Set the good IP if not already set
            if not self.good_ip:
                self.good_ip = ip
                
            # Store baseline data
            self.baseline_responses[baseline] = {"good_ip": ip}
            
            # Check NXDOMAIN responses
            test_domain = f"{self.generate_random_subdomain()}.{self.rootdomain}"
            nxsuccess, _ = self.resolve_query(baseline, test_domain)
            if nxsuccess:
                self.output.terminal(Level.ERROR, baseline, 
                                    f"Baseline server failed NXDOMAIN test for {test_domain}")
                return False
                
            # Check positive baselines (domains that should resolve)
            pos_results = {}
            for domain in self.positivebaselines:
                success, result = self.resolve_query(baseline, domain)
                if not success:
                    self.output.terminal(Level.ERROR, baseline, 
                                        f"Failed to resolve positive baseline {domain}")
                    return False
                pos_results[domain] = result
                
            self.baseline_responses[baseline]["positive_domains"] = pos_results
            
        return True
    
    def run(self) -> None:
        """Run the DNS validation process."""
        self.output.print_banner()
        
        # Establish baseline from trusted servers
        if not self.establish_baseline():
            self.output.terminal(Level.ERROR, "", "Failed to establish baseline. Exiting.")
            sys.exit(1)
        
        # Process target servers in parallel
        target_servers = InputHelper.return_targets(self.arguments)
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(self.arguments.threads)) as executor:
            # Submit all tasks
            futures = {executor.submit(self.validate_server, server): server for server in target_servers}
            
            # Process as they complete
            for future in concurrent.futures.as_completed(futures):
                server = futures[future]
                try:
                    future.result()  # Get result (or exception)
                except Exception as exc:
                    self.output.terminal(Level.ERROR, server, f"Generated an exception: {exc}")
        
        self.output.terminal(Level.INFO, "", f"Finished. Discovered {len(self.valid_servers)} valid servers")
        
        # Return the list of valid servers for potential use elsewhere
        return self.valid_servers


def signal_handler(signal, frame):
    """Handle keyboard interrupt gracefully."""
    print("\nExiting...")
    os._exit(0)


def main():
    """Main entry point for the application."""
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    parser = InputParser()
    arguments = parser.parse(sys.argv[1:])
    
    # Initialize and run the validator
    validator = DNSValidator(arguments)
    valid_servers = validator.run()
    
    # Output results to file if specified
    if arguments.output:
        with open(arguments.output, 'w') as f:
            for server in valid_servers:
                f.write(f"{server}\n")


if __name__ == "__main__":
    main()