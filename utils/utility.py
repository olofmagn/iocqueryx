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

"""
Utility functions
"""

def get_logger(name: str = "IocQueryx", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

# Use this on module level
logger = get_logger()

def extract_items(input_file: str) -> List[str]:
    """
    Args:
    - input_file (str): Path to the input file containing a list of items. Each line should include an IP address, domain, or file hash.

    Returns:
    - List[str]: A list containing only the first column (field) from each non-empty line in the input file.
    """

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            items = [line.strip().split(',')[0] for line in f if line.strip()]
            return items
    except FileNotFoundError as e:
        logger.error(
            f"File not found. Please check if you provided correct filepath {input_file}: {e}")
        sys.exit(1)
    except IOError as e:
        logger.error(f"Something unexpected happend: {e}")
        sys.exit(1)

def build_conditions(field: str, values: list, operator="AND", wrap_values: bool = False, quote_char: str = "'", comparator: str = "=") -> str:
    """
    Build a condition string joining multiple values with an operator.

    Args:
        field (str): The field name to filter on.
        values (list): List of values to include in the condition.
        operator (str): Logical operator to join conditions, e.g., "OR" or "AND".
        wrap_values (bool): Whether to wrap values in quotes.
        quote_char (str): The quote character to use if wrapping values.

    Returns:
        str: A combined condition string.
    """

    if not values:
        return ""

    def format_value(v):
        return f"{quote_char}{v}{quote_char}" if wrap_values else str(v)

    conditions = [
        f"{field}{comparator}{format_value(value)}" for value in values]
    return f" {operator} ".join(conditions)

def create_parser() -> argparse.ArgumentParser:
    """
    Parses and return command-line arguments

    Returns:
    - An instance of argparse
    """

    parser = argparse.ArgumentParser(description="Generate threat hunting queries for fast lookup of IOCs",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     )

    parser.add_argument("-i", "--input",
                        type=str,
                        required=True,
                        help="Path to the url/ip/hash file")

    parser.add_argument("-m", "--mode",
                        type=str,
                        required=True,
                        choices=["aql", "es", "defender"],
                        help="SIEM query mode")

    parser.add_argument("-l", "--lookback",
                        type=str,
                        help="Time lookback window for search (e.g., '24h', '7d')"
                        )

    parser.add_argument("-t", "--type",
                        type=str,
                        required=True,
                        choices=["ip", "domain", "hash"],
                        help="The type of parameter ioc parameter to use")

    parser.add_argument("-ht", "--hash_type",
                        type=str,
                        default="sha256",
                        choices=["md5", "sha1", "sha256"],
                        help="Hash type for hash queries (default: SHA256 Hash)")

    parser.add_argument("-q", "--qid",
                        type=int,
                        nargs="+",
                        help="Numeric representation of an event - e.g., firewall permit for qradar")

    parser.add_argument("-ea", "--event_action",
                        type=str,
                        nargs="+",
                        help="String representation of an event, - e.g., firewall permit for elastic")

    parser.add_argument("-o", "--output",
                        type=str,
                        help="Optional file to save query")

    return parser


def normalize_lookback(lookback: str, platform: str) -> None:
    """
    Normalizes the lookback to get correct values in elastic, qradar and defender.

    Args:
    - lookback (str): A lookback value normalised in the correct syntax.
    - platform (str): A platform 'aql', 'es' or 'defender'.
    """

    if not lookback:
        # default lookback
        lookback = "30 MINUTES"

    lookback = lookback.strip().upper()

    # CLI style (e.g. "10m", "5h", "1d")
    cli_pattern = r"^(\d+)([mhdMHD])$"
    match = re.match(cli_pattern, lookback)

    if match:
        value, unit = m.groups()
        # Map short units to long units
        short_to_long = {
            "M": "MINUTES",
            "H": "HOURS",
            "D": "DAYS",
        }

        if unit not in short_to_long:
            raise ValueError(f"Unsupported unit '{unit}' in CLI style lookback")
        normalized_unit = short_to_long[unit]
    else:
        # Try GUI style (e.g. "10 MINUTES") because we derive the logic from Qradar
        parts = lookback.split()
        if len(parts) != 2:
            raise ValueError(f"Invalid lookback format: '{lookback}' (expected '<value> <unit>')")

        value, unit = parts
        # Normalize unit plurals
        long_units = {
            "MINUTE": "MINUTES",
            "MINUTES": "MINUTES",
            "HOUR": "HOURS",
            "HOURS": "HOURS",
            "DAY": "DAYS",
            "DAYS": "DAYS",
        }

        if unit not in long_units:
            raise ValueError(f"Unsupported unit '{unit}' in GUI style lookback")
        normalized_unit = long_units[unit]

    if platform == "aql":
        # For AQL, keep long form with space
        return f"{value} {normalized_unit}"

    elif platform in ("es", "defender"):
        # For ES and Defender, convert long unit to short unit
        short_unit_map = {
            "MINUTES": "m",
            "HOURS": "h",
            "DAYS": "d",
        }
        short_unit = short_unit_map.get(normalized_unit)

        if not short_unit:
            raise ValueError(f"Unsupported unit '{normalized_unit}' for platform '{platform}'")
        return f"{value}{short_unit}"
    else:
        raise ValueError(f"Unknown platform '{platform}'")

