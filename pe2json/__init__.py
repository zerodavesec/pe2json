"""
PE2JSON - A utility to convert PE (Portable Executable) files to JSON format.
"""

from .pe2json import convert_to_serializable, pe_to_json

__version__ = "0.1.0"
__author__ = "David Martin"
__email__ = "zerodavesec@proton.me"

__all__ = ["pe_to_json", "convert_to_serializable"]
