#!/usr/bin/env python3

import sys
import requests
from urllib.parse import urlparse
from argparse import ArgumentParser
from pathlib import Path
from typing import Set, List, Optional, Union
import logging
from functools import lru_cache
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class InputHelper:
    """Helper class for processing input targets and validating arguments."""

    @staticmethod
    @lru_cache(maxsize=32)
    def process_targets(parser: ArgumentParser, arg: str) -> List[str]:
        """
        Process targets from URL or file.
        
        Args:
            parser: The argument parser for error reporting
            arg: Target source (URL or filename)
            
        Returns:
            List of target strings
            
        Raises:
            Exception: If no targets are found
        """
        targets = []
        
        if InputHelper.is_valid_url(arg):
            targets = InputHelper.fetch_url_content(parser, arg)
        else:
            filename = InputHelper.validate_filepath(parser, arg)
            if filename:
                targets = InputHelper.read_file_lines(filename)

        if not targets:
            parser.error(f"No targets found in {arg}")
            
        return targets

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Check if the provided string is a valid URL.
        
        Args:
            url: String to check
            
        Returns:
            True if valid URL, False otherwise
        """
        try:
            result = urlparse(url)
            return bool(result.scheme and result.netloc)
        except Exception:
            return False

    @staticmethod
    def validate_filepath(parser: ArgumentParser, filepath: str) -> Optional[str]:
        """
        Validate if the provided path points to an existing file.
        
        Args:
            parser: The argument parser for error reporting
            filepath: Path to validate
            
        Returns:
            Resolved absolute path as string if valid, None otherwise
        """
        try:
            path = Path(filepath).expanduser().resolve()
            if not path.is_file():
                parser.error(f"The file {filepath} does not exist!")
                return None
            return str(path)
        except Exception as e:
            parser.error(f"Error validating file {filepath}: {str(e)}")
            return None

    @staticmethod
    def fetch_url_content(parser: ArgumentParser, url: str) -> List[str]:
        """
        Fetch content from URL with retries and timeouts.
        
        Args:
            parser: The argument parser for error reporting
            url: URL to fetch content from
            
        Returns:
            List of strings from the URL content
        """
        session = requests.Session()
        
        # Configure retries for robustness
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        try:
            response = session.get(url, timeout=(3.05, 10))
            response.raise_for_status()
            return [line for line in response.text.split() if line.strip()]
        except requests.exceptions.RequestException as e:
            parser.error(f"Failed to fetch content from {url}: {str(e)}")
            return []
        finally:
            session.close()

    @staticmethod
    def read_file_lines(filepath: str) -> List[str]:
        """
        Read lines from file efficiently.
        
        Args:
            filepath: Path to the file
            
        Returns:
            List of non-empty lines
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            logging.error(f"Error reading file {filepath}: {str(e)}")
            return []

    @staticmethod
    def check_positive(parser: ArgumentParser, arg: str) -> int:
        """
        Validate that argument is a positive integer.
        
        Args:
            parser: The argument parser for error reporting
            arg: Value to check
            
        Returns:
            Integer value if positive
            
        Raises:
            ArgumentTypeError: If not a positive integer
        """
        try:
            value = int(arg)
            if value <= 0:
                parser.error(f"{arg} is not a valid positive integer!")
            return value
        except ValueError:
            parser.error(f"{arg} is not a valid integer!")

    @staticmethod
    def get_targets(arguments) -> Set[str]:
        """
        Process targets and exclusions to return final target set.
        
        Args:
            arguments: Parsed command line arguments
            
        Returns:
            Set of target strings after applying exclusions
            
        Raises:
            Exception: If no targets remain after exclusions
        """
        # Use sets for efficient operations
        targets: Set[str] = set()
        exclusions: Set[str] = set()
        
        # Process targets
        if arguments.target:
            targets.add(arguments.target)
        elif arguments.target_list:
            targets.update(arguments.target_list)
            
        # Process exclusions
        if arguments.exclusion:
            exclusions.add(arguments.exclusion)
        elif arguments.exclusions_list:
            exclusions.update(arguments.exclusions_list)
            
        # Apply exclusions efficiently
        final_targets = targets - exclusions
        
        if not final_targets:
            raise ValueError("No targets remain after applying exclusions.")
            
        return final_targets


class InputParser:
    """Parser for command line arguments."""

    def __init__(self):
        """Initialize the argument parser."""
        self._parser = self._create_parser()

    def parse(self, argv: List[str]):
        """
        Parse command line arguments.
        
        Args:
            argv: List of command line arguments
            
        Returns:
            Parsed arguments object
        """
        return self._parser.parse_args(argv)

    def _create_parser(self) -> ArgumentParser:
        """
        Create and configure the argument parser.
        
        Returns:
            Configured ArgumentParser instance
        """
        parser = ArgumentParser(description="DNS Validator - Find valid DNS servers")
        
        # Target group
        target_group = parser.add_mutually_exclusive_group(required=False)
        target_group.add_argument(
            '-t', dest='target', 
            help='Specify a single target DNS server'
        )
        target_group.add_argument(
            '-tL', dest='target_list',
            help='Specify a list of target DNS servers (file or URL)',
            default="https://public-dns.info/nameservers.txt",
            type=lambda x: InputHelper.process_targets(parser, x)
        )

        # Exclusions group
        exclusion_group = parser.add_mutually_exclusive_group()
        exclusion_group.add_argument(
            '-e', dest='exclusion',
            help='Specify a single DNS server to exclude'
        )
        exclusion_group.add_argument(
            '-eL', dest='exclusions_list',
            help='Specify a list of DNS servers to exclude (file or URL)',
            type=lambda x: InputHelper.process_targets(parser, x)
        )

        # Output options
        parser.add_argument(
            '-o', '--output', dest='output',
            help='File to write valid DNS servers to'
        )

        # DNS validation options
        parser.add_argument(
            '-r', dest='rootdomain', default="bet365.com",
            help='Root domain for DNS validation (default: bet365.com)'
        )
        parser.add_argument(
            '-q', dest='query', default="dnsvalidator",
            help='Query string for resolution tests (default: dnsvalidator)'
        )

        # Performance options
        parser.add_argument(
            '-threads', dest='threads', default=5,
            type=lambda x: InputHelper.check_positive(parser, x),
            help='Maximum number of concurrent threads (default: 5)'
        )
        parser.add_argument(
            '-timeout', dest='timeout', default=600,
            type=lambda x: InputHelper.check_positive(parser, x),
            help='Operation timeout in seconds (default: 600)'
        )

        # Display options
        parser.add_argument(
            '--no-color', dest='nocolor', action='store_true', default=False,
            help='Disable colored output'
        )
        
        output_group = parser.add_mutually_exclusive_group()
        output_group.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true', default=False,
            help='Enable verbose output'
        )
        output_group.add_argument(
            '--silent', dest='silent', action='store_true', default=False,
            help='Suppress all non-essential output'
        )

        return parser