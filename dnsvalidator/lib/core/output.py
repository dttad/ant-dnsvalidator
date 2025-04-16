#!/usr/bin/env python3

from colorclass import Color, disable_all_colors, is_enabled
from enum import IntEnum
from time import localtime, strftime
from typing import Optional, Dict, Union, TextIO
import os
from contextlib import contextmanager
from functools import lru_cache

# Import version from the package
try:
    from dnsvalidator.lib.core.__version__ import __version__
except ImportError:
    # Fallback if not imported as package
    __version__ = "unknown"


class Level(IntEnum):
    """Enumeration of output message levels."""
    VERBOSE = 0
    INFO = 1
    ACCEPTED = 2
    REJECTED = 3
    ERROR = 4
    
    @classmethod
    @lru_cache(maxsize=8)
    def get_formatting(cls, level: int) -> str:
        """
        Get color formatting for the specified level.
        
        Args:
            level: Output level from the Level enum
            
        Returns:
            Colorized string for the level
        """
        formatting_map = {
            cls.VERBOSE: '{autoblue}[VERBOSE]{/autoblue}',
            cls.INFO: '{autoyellow}[INFO]{/autoyellow}',
            cls.ACCEPTED: '{autogreen}[ACCEPTED]{/autogreen}',
            cls.REJECTED: '{autored}[REJECTED]{/autored}',
            cls.ERROR: '{autobgyellow}{autored}[ERROR]{/autored}{/autobgyellow}'
        }
        return Color(formatting_map.get(level, '[#]'))


class OutputHelper:
    """Helper class for formatting and managing console and file output."""
    
    def __init__(self, arguments):
        """
        Initialize the OutputHelper with command-line arguments.
        
        Args:
            arguments: Parsed command-line arguments
        """
        # Set color mode
        if getattr(arguments, 'nocolor', False):
            disable_all_colors()
            
        # Set output options
        self.verbose = getattr(arguments, 'verbose', False)
        self.silent = getattr(arguments, 'silent', False)
        self.output_file = getattr(arguments, 'output', None)
        
        # Initialize output file if specified
        self._output_stream = None
        if self.output_file:
            self._setup_output_file()
            
        # Constants
        self.separator = "=" * 55
        
    def _setup_output_file(self) -> None:
        """Set up the output file, creating the directory if needed."""
        if not self.output_file:
            return
            
        try:
            # Create directory if it doesn't exist
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(f"Error creating output directory: {e}", flush=True)
            self.output_file = None
    
    @contextmanager
    def _get_output_stream(self) -> TextIO:
        """
        Context manager for the output file.
        
        Returns:
            File handle for writing
        """
        if not self.output_file:
            raise ValueError("No output file specified")
            
        try:
            with open(self.output_file, 'a+', encoding='utf-8') as f:
                yield f
        except IOError as e:
            print(f"Error writing to output file: {e}", flush=True)
            # Fall back to console output
            yield None
    
    def print_banner(self) -> None:
        """Print the application banner unless in silent mode."""
        if self.silent:
            return

        print(self.separator, flush=True)
        print(f"dnsvalidator v{__version__}\tby James McLean (@vortexau) "
              f"\n                \t& Michael Skelton (@codingo_)", flush=True)
        print(self.separator, flush=True)

    def terminal(self, level: Union[Level, int], target: Union[str, int], message: str = "") -> None:
        """
        Output a message to the terminal with appropriate formatting.
        
        Args:
            level: Message level (from Level enum)
            target: Target being processed, or 0 for generic messages
            message: Optional message to display
        """
        # Handle verbosity rules
        if level == Level.VERBOSE and not self.verbose:
            return

        # In silent mode, only print ACCEPTED targets
        if self.silent:
            if level == Level.ACCEPTED:
                print(target, flush=True)
                # Write to output file if specified
                self._write_accepted_target(target)
            return

        # Get colorized leader based on level
        leader = Level.get_formatting(level)
        
        # Format the timestamp
        timestamp = strftime("%H:%M:%S", localtime())
        
        # Format the output differently based on target
        if target == 0:
            formatted_message = f"[{timestamp}] {leader} {message}"
        else:
            formatted_message = f"[{timestamp}] {leader} [{target}] {message}"
            
        print(formatted_message, flush=True)
        
        # Write accepted targets to output file
        if level == Level.ACCEPTED and isinstance(target, str):
            self._write_accepted_target(target)
            
    def _write_accepted_target(self, target: str) -> None:
        """
        Write an accepted target to the output file.
        
        Args:
            target: Target to write to the file
        """
        if not self.output_file:
            return
            
        try:
            with self._get_output_stream() as f:
                if f:
                    f.write(f"{target}\n")
        except Exception:
            # Already logged in _get_output_stream
            pass
            
    def write_targets(self, targets: list) -> None:
        """
        Write multiple targets to the output file efficiently.
        
        Args:
            targets: List of targets to write
        """
        if not self.output_file or not targets:
            return
            
        try:
            with self._get_output_stream() as f:
                if f:
                    for target in targets:
                        f.write(f"{target}\n")
        except Exception:
            # Already logged in _get_output_stream
            pass