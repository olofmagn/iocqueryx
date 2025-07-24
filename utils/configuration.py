"""
A simple program that generates a search query based on a given list.

Author: Olof Magnusson
Date: 2025-07-02
"""

import re
import argparse
import logging

from typing import Optional, List, Tuple

from utils.ui_constants import (
    DEFAULT_LOGGER_NAME,
    DEFAULT_LOG_LEVEL,
    DEFAULT_ENCODING,
    DEFAULT_HASH_TYPE,
    FIRST_COLUMN_INDEX,
    LOG_FORMAT,
    SUPPORTED_MODES,
    SUPPORTED_TYPES,
    SUPPORTED_HASH_TYPES,
    TIME_UNIT_PATTERNS,
    PLATFORM_HASH_TYPES,
    LOOKBACK_PATTERN,
    DEFENDER_ES_PLATFORMS,
    CSV_DELIMITER,
)


# =============================================================================
# LOGGING UTILITIES
# =============================================================================


def get_logger(
        name: str = DEFAULT_LOGGER_NAME, level: int = DEFAULT_LOG_LEVEL
) -> logging.Logger:
    """
    Logger utility

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


def _create_module_logger() -> logging.Logger:
    """
    Create module logger
    """

    return get_logger()


# Module-level logger
logger = _create_module_logger()


# =============================================================================
# FILE PROCESSING UTILITIES
# =============================================================================


def _read_file_lines(file_path: str, encoding: str = DEFAULT_ENCODING) -> List[str]:
    """
    Read file lines.

    Args:
    - file_path (str): File path to read
    - encoding (str): File encoding (default: utf-8)

    Returns:
    - List[str]: List of non-empty lines from the file
    """

    # Validate input at the point of use
    if not file_path or not file_path.strip():
        raise ValueError("File path cannot be empty")

    try:
        with open(file_path, "r", encoding=encoding) as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            raise ValueError(f"File {file_path} is empty or contains no valid data")
        return lines
    except FileNotFoundError:
        raise ValueError(f"File not found: {file_path}")
    except PermissionError:
        raise ValueError(f"Permission denied reading file: {file_path}")
    except UnicodeDecodeError:
        raise ValueError(f"Cannot decode file {file_path} with encoding {encoding}")
    except IOError as e:
        raise ValueError(f"Error reading file {file_path}: {e}")


def extract_items(file_path: str) -> List[str]:
    """
    Extract items

    Args:
    - file_path (str): Path to the input file containing a list of items

    Returns:
    - List[str]: List containing only the first column from each non-empty line
    """

    lines = _read_file_lines(file_path)

    return [_extract_first_column(line) for line in lines]


def _extract_first_column(line: str, delimiter: str = CSV_DELIMITER) -> str:
    """
    Extract first column

    Args:
    - line (str): Line to process
    - delimiter (str): Column delimiter (default: comma)

    Returns:
    - str: First column value
    """

    return line.split(delimiter)[FIRST_COLUMN_INDEX]


# =============================================================================
# QUERY CONDITION UTILITIES
# =============================================================================


def get_supported_hash_types(mode: str) -> List[str]:
    """
    Get supported hash types for a specific mode.

    Args:
    - mode (str): Platform mode (e.g., 'aql', 'es', 'defender')

    Returns:
    - List[str]: List of supported hash types for the mode
    """

    return PLATFORM_HASH_TYPES.get(mode.lower(), SUPPORTED_HASH_TYPES)


def _format_condition_value(
        value, wrap_values: bool = False, quote_char: str = "'"
) -> str:
    """
    Format condition value

    Args:
    - value: Value to format
    - wrap_values (bool): Whether to wrap values in quotes
    - quote_char (str): Quote character to use

    Returns:
    - str: Formatted value
    """

    return f"{quote_char}{value}{quote_char}" if wrap_values else str(value)


def create_single_condition(
        field: str,
        value,
        comparator: str = "=",
        wrap_values: bool = False,
        quote_char: str = "'",
) -> str:
    """
    Create single condition

    Args:
    - field (str): Field name
    - value: Value to compare
    - comparator (str): Comparison operator
    - wrap_values (bool): Whether to wrap values in quotes
    - quote_char (str): Quote character to use

    Returns:
    - str: Single condition string
    """

    formatted_value = _format_condition_value(value, wrap_values, quote_char)

    return f"{field}{comparator}{formatted_value}"


def build_conditions(
        field: str,
        values: list,
        operator: str = "AND",
        wrap_values: bool = False,
        quote_char: str = "'",
        comparator: str = "=",
) -> str:
    """
    Build conditions

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


def _validate_time_value(value: int) -> bool:
    """
    Validate time value

    Args:
    - value (int): Time value to validate

    Returns:
    - bool: True if value is positive
    """

    return value > 0


def _normalize_time_unit(unit: str) -> Optional[str]:
    """
    Normalize time unit

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


def _parse_lookback_string(lookback: str) -> Optional[Tuple[int, str]]:
    """
    Parse lookback string

    Args:
    - lookback (str): Lookback string to parse (e.g., "24h", "7d")

    Returns:
    - Optional[Tuple[int, str]]: (value, normalized_unit) or None if invalid
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

    if not _validate_time_value(value):
        return None

    normalized_unit = _normalize_time_unit(unit)

    if normalized_unit is None:
        return None

    return value, normalized_unit


def _format_time_for_platform(value: int, unit: str, mode: str) -> str | None:
    """
    Format time for platform

    Args:
    - value (int): Time value
    - unit (str): Normalized time unit (minutes/hours/days)
    - mode (str): Platform mode (aql/es/defender)

    Returns:
    - str: Formatted time string for the platform
    """

    is_defender_or_elastic = mode.lower() in DEFENDER_ES_PLATFORMS

    match unit:
        case "minutes":
            return f"{value}m" if is_defender_or_elastic else f"{value} MINUTES"
        case "hours":
            return f"{value}h" if is_defender_or_elastic else f"{value} HOURS"
        case "days":
            return f"{value}d" if is_defender_or_elastic else f"{value} DAYS"
        case _:
            return None


def normalize_lookback(lookback: str, mode: str) -> Optional[str]:
    """
    Normalize lookback

    Args:
    - lookback (str): The string value to transform to correct format
    - mode (str): The mode 'defender', 'es' or 'aql'

    Returns:
    - Optional[str]: A lookback value in the correct format for query iteration
    """

    if not lookback or not mode:
        return None

    parsed = _parse_lookback_string(lookback)

    if parsed is None:
        return None

    value, unit = parsed

    return _format_time_for_platform(value, unit, mode)


# =============================================================================
# ARGUMENT PARSER UTILITIES
# =============================================================================


def _create_base_parser() -> argparse.ArgumentParser:
    """
    Create base parser
    """

    return argparse.ArgumentParser(
        description="Generate threat hunting queries for fast lookup of IOCs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def _add_required_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add required arguments
    """

    parser.add_argument(
        "-i", "--input", type=str, required=True, help="Path to the url/ip/hash file"
    )

    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        required=True,
        choices=SUPPORTED_MODES,
        help="SIEM query mode",
    )

    parser.add_argument(
        "-l",
        "--lookback",
        type=str,
        required=True,
        help="Time lookback window for search (e.g., '24h', '7d')",
    )

    parser.add_argument(
        "-t",
        "--type",
        type=str,
        required=True,
        choices=SUPPORTED_TYPES,
        help="The type of parameter ioc parameter to use",
    )


def _add_optional_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Add optional arguments
    """

    parser.add_argument(
        "-ht",
        "--hash_type",
        type=str,
        default=DEFAULT_HASH_TYPE,
        choices=SUPPORTED_HASH_TYPES,
        help=f"Hash type for hash queries (default: {DEFAULT_HASH_TYPE.upper()})",
    )

    parser.add_argument(
        "-q",
        "--qid",
        type=int,
        nargs="+",
        help="Numeric representation of an event - e.g., firewall permit for qradar",
    )

    parser.add_argument(
        "-ea",
        "--event_action",
        type=str,
        nargs="+",
        help="String representation of an event - e.g., firewall permit for elastic",
    )

    parser.add_argument("-o", "--output", type=str, help="Optional file to save query")

    parser.add_argument(
        "-p",
        "--project",
        action="store_true",
        help="Apply field projection for Defender queries",
    )


def create_parser() -> argparse.ArgumentParser:
    """
    Create parser logic
    """

    parser = _create_base_parser()
    _add_required_arguments(parser)
    _add_optional_arguments(parser)

    return parser
