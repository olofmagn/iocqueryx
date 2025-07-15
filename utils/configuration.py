"""
A simple program that generates a search query based on a given list.

Author: Olof Magnusson
Date: 2025-07-02
"""

import re
import sys
import argparse
import logging
from typing import Optional, List, Dict

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

# Application Configuration
DEFAULT_LOGGER_NAME = "IocQueryx"
DEFAULT_LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# Supported Values
SUPPORTED_MODES = ["aql", "es", "defender"]
SUPPORTED_TYPES = ["ip", "domain", "hash"]
SUPPORTED_HASH_TYPES = ["md5", "sha1", "sha256"]

# Default Values
DEFAULT_HASH_TYPE = "sha256"
DEFAULT_ENCODING = "utf-8"

# Time Unit Mappings
TIME_UNIT_PATTERNS = {
    "minutes": ["minute", "minutes", "min", "m"],
    "hours": ["hour", "hours", "h"],
    "days": ["day", "days", "d"]
}

# Platform-specific time formats
DEFENDER_ES_PLATFORMS = ["defender", "es"]
AQL_PLATFORM = "aql"

# Regex Patterns
LOOKBACK_PATTERN = r"(\d+)\s*(minutes?|hours?|days?|min|m|h|d)"

# File Processing Configuration
CSV_DELIMITER = ","
FIRST_COLUMN_INDEX = 0

# =============================================================================
# LOGGING UTILITIES
# =============================================================================

def get_logger(name: str = DEFAULT_LOGGER_NAME, level: int = DEFAULT_LOG_LEVEL) -> logging.Logger:
    """
    get_logger utility.

    Args:
    - name (str): Logger name (default: IocQueryx)
    - level (int): Logging level (default: INFO)
    Returns:
    - logging.Logger: Configured logger instance
    """

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

def create_module_logger() -> logging.Logger:
    """
    Create module logger.
    """

    return get_logger()

# Module-level logger
logger = create_module_logger()

# =============================================================================
# FILE PROCESSING UTILITIES
# =============================================================================

def validate_file_path(file_path: str) -> bool:
    """
    Validate file path.
    
    Args:
    - file_path (str): Path to validate
    Returns:
    - bool: True if file path is valid string
    """
    return bool(file_path and file_path.strip())

def read_file_lines(file_path: str, encoding: str = DEFAULT_ENCODING) -> List[str]:
    """
    Read file lines.

    Args:
    - file_path (str): Path to the file to read
    - encoding (str): File encoding (default: utf-8)
    Returns:
    - List[str]: List of non-empty lines from the file
    """

    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        logger.error(f"File not found. Please check if you provided correct filepath {file_path}: {e}")
    except IOError as e:
        logger.error(f"Something unexpected happened: {e}")

def extract_first_column(line: str, delimiter: str = CSV_DELIMITER) -> str:
    """
    Args:
    - line (str): Line to process
    - delimiter (str): Column delimiter (default: comma)
    Returns:
    - str: First column value
    """
    return line.split(delimiter)[FIRST_COLUMN_INDEX]

def extract_items(input_file: str) -> List[str]:
    """
    Extract items.

    Args:
    - input_file (str): Path to the input file containing a list of items

    Returns:
    - List[str]: List containing only the first column from each non-empty line
    """

    if not validate_file_path(input_file):
        logger.error("Invalid file path provided")
        sys.exit(1)
    
    lines = read_file_lines(input_file)
    return [extract_first_column(line) for line in lines]

# =============================================================================
# QUERY CONDITION UTILITIES
# =============================================================================

def format_condition_value(value, wrap_values: bool = False, quote_char: str = "'") -> str:
    """
    Format condition value.

    Args:
    - value: Value to format
    - wrap_values (bool): Whether to wrap values in quotes
    - quote_char (str): Quote character to use

    Returns:
    - str: Formatted value
    """

    return f"{quote_char}{value}{quote_char}" if wrap_values else str(value)

def create_single_condition(field: str, value, comparator: str = "=", wrap_values: bool = False, quote_char: str = "'") -> str:
    """
    Args:
    - field (str): Field name
    - value: Value to compare
    - comparator (str): Comparison operator
    - wrap_values (bool): Whether to wrap values in quotes
    - quote_char (str): Quote character to use

    Returns:
    - str: Single condition string
    """

    formatted_value = format_condition_value(value, wrap_values, quote_char)
    return f"{field}{comparator}{formatted_value}"

def build_conditions(field: str, values: list, operator: str = "AND", wrap_values: bool = False, quote_char: str = "'", comparator: str = "=") -> str:
    """
    Build conditions.

    Args:
    - field (str): The field name to filter on
    - values (list): List of values to include in the condition
    - operator (str): Logical operator to join conditions (AND/OR)
    - wrap_values (bool): Whether to wrap values in quotes
    - quote_char (str): The quote character to use if wrapping values
    - comparator (str): Comparison operator (=, :, etc.)

    Returns:
    - str: A combined condition string
    """

    if not values:
        return ""

    conditions = [
        create_single_condition(field, value, comparator, wrap_values, quote_char) 
        for value in values
    ]
    return f" {operator} ".join(conditions)

# =============================================================================
# TIME PROCESSING UTILITIES
# =============================================================================

def validate_time_value(value: int) -> bool:
    """
    Validate time value.

    Args:
    - value (int): Time value to validate

    Returns:
    - bool: True if value is positive
    """

    return value > 0

def normalize_time_unit(unit: str) -> Optional[str]:
    """
    Args:
    - unit (str): Time unit string to normalize

    Returns:
    - Optional[str]: Normalized unit (minutes/hours/days) or None if invalid
    """

    unit_lower = unit.lower()
    
    for normalized_unit, patterns in TIME_UNIT_PATTERNS.items():
        if unit_lower in patterns:
            return normalized_unit
    
    return None

def parse_lookback_string(lookback: str) -> Optional[tuple[int, str]]:
    """
    Parse lookback string.

    Args:
    - lookback (str): Lookback string to parse (e.g., "24h", "7d")

    Returns:
    - Optional[tuple[int, str]]: (value, normalized_unit) or None if invalid
    """

    lookback = lookback.strip()
    match = re.match(LOOKBACK_PATTERN, lookback, re.IGNORECASE)

    if not match:
        return None

    value_str, unit = match.groups()
    
    try:
        value = int(value_str)
    except ValueError:
        return None
    
    if not validate_time_value(value):
        return None
    
    normalized_unit = normalize_time_unit(unit)
    if normalized_unit is None:
        return None
    
    return value, normalized_unit

def format_time_for_platform(value: int, unit: str, mode: str) -> str:
    """
    Format time for platform.

    Args:
    - value (int): Time value
    - unit (str): Normalized time unit (minutes/hours/days)
    - mode (str): Platform mode (aql/es/defender)
    Returns:
    - str: Formatted time string for the platform
    """
    
    is_defender_or_elastic = mode.lower() in DEFENDER_ES_PLATFORMS
    
    if unit == "minutes":
        return f"{value}m" if is_defender_or_elastic else f"{value} MINUTES"
    elif unit == "hours":
        return f"{value}h" if is_defender_or_elastic else f"{value} HOURS"
    elif unit == "days":
        if is_defender_or_elastic:
            # Convert days to hours for Defender/Elastic
            return f"{value * 24}h"
        else:
            return f"{value} DAYS"
    
    return None

def normalize_lookback(lookback: str, mode: str) -> Optional[str]:
    """
    Normalize lookback.

    Args:
    - lookback (str): The string value to transform to correct format
    - mode (str): The mode 'defender', 'es' or 'aql'

    Returns:
    - Optional[str]: A lookback value in the correct format for query iteration
    """

    if not lookback or not mode:
        return None
    
    parsed = parse_lookback_string(lookback)
    if parsed is None:
        return None
    
    value, unit = parsed
    return format_time_for_platform(value, unit, mode)

# =============================================================================
# ARGUMENT PARSER UTILITIES
# =============================================================================

def create_base_parser() -> argparse.ArgumentParser:
    """
    Create base parser
    """

    return argparse.ArgumentParser(
        description="Generate threat hunting queries for fast lookup of IOCs",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

def add_required_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add required arguments
    """

    parser.add_argument("-i", "--input",
                        type=str,
                        required=True,
                        help="Path to the url/ip/hash file")

    parser.add_argument("-m", "--mode",
                        type=str,
                        required=True,
                        choices=SUPPORTED_MODES,
                        help="SIEM query mode")

    parser.add_argument("-l", "--lookback",
                        type=str,
                        required=True,
                        help="Time lookback window for search (e.g., '24h', '7d')")

    parser.add_argument("-t", "--type",
                        type=str,
                        required=True,
                        choices=SUPPORTED_TYPES,
                        help="The type of parameter ioc parameter to use")

def add_optional_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add optional arguments.
    """

    parser.add_argument("-ht", "--hash_type",
                        type=str,
                        default=DEFAULT_HASH_TYPE,
                        choices=SUPPORTED_HASH_TYPES,
                        help=f"Hash type for hash queries (default: {DEFAULT_HASH_TYPE.upper()})")

    parser.add_argument("-q", "--qid",
                        type=int,
                        nargs="+",
                        help="Numeric representation of an event - e.g., firewall permit for qradar")

    parser.add_argument("-ea", "--event_action",
                        type=str,
                        nargs="+",
                        help="String representation of an event - e.g., firewall permit for elastic")

    parser.add_argument("-o", "--output",
                        type=str,
                        help="Optional file to save query")

def create_parser() -> argparse.ArgumentParser:
    """
    Create parser logic.
    """

    parser = create_base_parser()
    add_required_arguments(parser)
    add_optional_arguments(parser)
    return parser

# =============================================================================
# VALIDATION UTILITIES
# =============================================================================

def validate_mode(mode: str) -> bool:
    """
    Validate mode.

    Args:
    - mode (str): Mode to validate

    Returns:
    - bool: True if mode is supported
    """

    return mode.lower() in SUPPORTED_MODES

def validate_type(item_type: str) -> bool:
    """
    Args:
    - item_type (str): Type to validate

    Returns:
    - bool: True if type is supported
    """

    return item_type.lower() in SUPPORTED_TYPES

def validate_hash_type(hash_type: str) -> bool:
    """
    Args:
    - hash_type (str): Hash type to validate
    
    Returns:
    - bool: True if hash type is supported
    """

    return hash_type.lower() in SUPPORTED_HASH_TYPES

def validate_configuration_parameters(mode: str, item_type: str, hash_type: str = None) -> tuple[bool, str]:
    """
    Args:
    - mode (str): Mode to validate
    - item_type (str): Type to validate
    - hash_type (str): Hash type to validate (optional)

    Returns:
    - tuple[bool, str]: (is_valid, error_message)
    """

    if not validate_mode(mode):
        return False, f"Unsupported mode: {mode}. Must be one of: {SUPPORTED_MODES}"
    
    if not validate_type(item_type):
        return False, f"Unsupported type: {item_type}. Must be one of: {SUPPORTED_TYPES}"
    
    if item_type.lower() == "hash" and hash_type and not validate_hash_type(hash_type):
        return False, f"Unsupported hash type: {hash_type}. Must be one of: {SUPPORTED_HASH_TYPES}"
    
    return True, ""

# =============================================================================
# CONFIGURATION INFO UTILITIES
# =============================================================================

def get_supported_configurations() -> Dict[str, List[str]]:
    """
    Get supported configurations
    """

    return {
        "modes": SUPPORTED_MODES,
        "types": SUPPORTED_TYPES,
        "hash_types": SUPPORTED_HASH_TYPES
    }

def get_time_unit_examples() -> Dict[str, List[str]]:
    """
    Get time unit examples
    """

    return {
        "minutes": ["5m", "10min", "30 minutes"],
        "hours": ["1h", "3hours", "12 h"],
        "days": ["1d", "7days", "30 d"]
    }

def get_platform_time_formats() -> Dict[str, Dict[str, str]]:
    """
    Get platform time formats
    """

    return {
        "aql": {
            "minutes": "30 MINUTES",
            "hours": "2 HOURS", 
            "days": "7 DAYS"
        },
        "defender": {
            "minutes": "30m",
            "hours": "2h",
            "days": "168h"  # 7 days = 168 hours
        },
        "es": {
            "minutes": "30m",
            "hours": "2h", 
            "days": "168h"  # 7 days = 168 hours
        }
    }