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
                        required=True,
                        help="Time lookback window for search (e.g., '24h', '7d')",
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


def normalize_lookback(lookback: str, mode: str) -> str:

    """
    Normalises lookback values for Defender/Elastic platform.

    Args:
    - lookback (str): The string value to transform to correct format.
    - mode (str): The mode 'defender', 'es' or 'aql'.

    Returns:
    - str: A lookback value in the correct format for query iteration.
    """
    lookback = lookback.strip().lower()
    match = re.match(r"(\d+)\s*(minutes?|hours?|days?|min|m|h|d)", lookback, re.IGNORECASE)

    if not match:
        return None

    value, unit = match.groups()
    value = int(value)

    # Positive values
    if value <= 0:
        return None

    is_defender_or_elastic = mode in ("defender", "es")

    match unit:
        case "minute" | "minutes" | "min" | "m":
            return f"{value}m" if is_defender_or_elastic else f"{value} MINUTES"
        case "hour" | "hours" | "h":
            return f"{value}h" if is_defender_or_elastic else f"{value} HOURS"
        case "day" | "days" | "d":
            return f"{value*24}h" if is_defender_or_elastic else f"{value} DAYS"
        case _:
            return None
