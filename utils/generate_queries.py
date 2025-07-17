"""
A simple program that generates a search query based on a given list

Author: Olof Magnusson
Date: 2025-07-02
"""

import argparse

from typing import List, Optional, Union, Dict

from .configuration import (
    create_parser,
    extract_items,
    build_conditions,
    normalize_lookback,
)

from utils.ui_constants import (
    DEFAULT_HASH_TYPE,
    PLATFORM_HASH_TYPES,
    SUPPORTED_HASH_TYPES,
    SUPPORTED_MODES,
    SUPPORTED_ITEM_TYPES
)

"""
Generate queries based on provided platform 'aql', 'elastic' or 'defender
"""

# =============================================================================
# PLATFORM FIELD MAPPINGS AND CONSTANTS
# =============================================================================


# AQL Platform Field Mappings
AQL_FIELDS = {
    "ip": "sourceip",
    "domain": "\"URL Domain\"",
    "hash": {
        "filehash": "\"File Hash\"",
        "md5": "\"MD5 Hash\"",
        "sha1": "\"SHA1 Hash\"",
        "sha256": "\"SHA256 Hash\""
    }
}

# Elasticsearch Platform Field Mappings
ELASTIC_FIELDS = {
    "ip": "source.ip",
    "domain": "url.domain",
    "hash": {
        "md5": "file.hash.md5",
        "sha1": "file.hash.sha1",
        "sha256": "file.hash.sha256"
    }
}

# Microsoft Defender Platform Configuration
DEFENDER_FIELDS = {
    "ip": {
        "field": "RemoteIP",
        "table": "DeviceNetworkEvents"
    },
    "domain": {
        "field": "RemoteUrl",
        "table": "DeviceNetworkEvents"
    },
    "hash": {
        "table": "DeviceFileEvents",
        "fields": {
            "md5": "InitiatingProcessMD5",
            "sha1": "InitiatingProcessSHA1",
            "sha256": "SHA256"
        }
    }
}


# =============================================================================
# VALIDATION UTILITY FUNCTIONS
# =============================================================================

def _validate_item_type(item_type: str) -> None:
    """
    Validate item type.

    Args:
    - item_type (str): Type of item to validate

    Raises:
    - ValueError: If item_type is not supported
    """
    if item_type not in SUPPORTED_ITEM_TYPES:
        raise ValueError(f"Unsupported item_type: {item_type}. Must be one of: {SUPPORTED_ITEM_TYPES}")


def _validate_hash_type(hash_type: str, mode: str = None) -> None:
    """
    Validate hash type for specific mode.

    Args:
    - hash_type (str): Hash type to validate
    - mode (str): Platform mode for validation (optional)

    Raises:
    - ValueError: If hash_type is not supported
    """

    supported_types = PLATFORM_HASH_TYPES.get(mode, SUPPORTED_HASH_TYPES) if mode else SUPPORTED_HASH_TYPES

    if hash_type.lower() not in supported_types:
        raise ValueError(f"Unsupported hash_type: {hash_type}. Must be one of: {supported_types}")


def _get_field_for_platform(platform_fields: Dict, item_type: str, hash_type: str, mode: str = None) -> str:
    """
    Get field for a specific platform.

    Args:
    - platform_fields (Dict): Platform-specific field mappings
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items
    - mode (str): Platform mode for validation (optional)

    Returns:
    - str: Field name for the platform
    """

    _validate_item_type(item_type)

    if item_type == "hash":
        _validate_hash_type(hash_type, mode)
        return platform_fields["hash"][hash_type.lower()]

    return platform_fields[item_type]


# =============================================================================
# FIELD MAPPING HELPER FUNCTIONS
# =============================================================================

def get_aql_field(item_type: str, hash_type: str = DEFAULT_HASH_TYPE) -> str:
    """
    Get AQL field.

    Args:
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items (default: sha256)

    Returns:
    - str: AQL field name
    """

    return _get_field_for_platform(AQL_FIELDS, item_type, hash_type, "aql")


def get_elastic_field(item_type: str, hash_type: str = DEFAULT_HASH_TYPE) -> str:
    """
    Get Elastic field.

    Args:
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items (default: sha256)

    Returns:
    - str: Elastic field name
    """

    return _get_field_for_platform(ELASTIC_FIELDS, item_type, hash_type, "es")


def get_defender_fields(item_type: str, hash_type: str = DEFAULT_HASH_TYPE) -> Dict[str, str]:
    """
    Get Defender config.

    Args:
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items (default: sha256)

    Returns:
    - Dict[str, str]: Dictionary with 'field' and 'table' keys
    """

    _validate_item_type(item_type)

    config = DEFENDER_FIELDS[item_type].copy()

    if item_type == "hash":
        _validate_hash_type(hash_type, "defender")
        config["field"] = config["fields"][hash_type.lower()]
        del config["fields"]  # Clean up the nested structure

    return config


# =============================================================================
# QUERY GENERATION FUNCTIONS
# =============================================================================

def generate_aql_query(items: List[str], item_type: str, qids: Optional[List[int]] = None, hash_type: str = "sha256",
                       lookback: str = None) -> str:
    """
    Generate AQL query

    Args:
    - items (List[str]): A list of items, e.g., ip, domains or hashes.
    - item_type (str): The type of item - must be one of 'ip', 'domain' or 'hash'.
    - qids (Optional[List[int]]): Optional QID numbers for filtering.
    - hash_type (str): Hash type for hash queries (default: sha256).
    - lookback (str): Time range for the query.

    Returns:
    - str: AQL query string
    """

    qids = qids or []

    field = get_aql_field(item_type, hash_type)

    qid_condition = build_conditions(
        "qid", qids, operator="or", wrap_values=True, comparator="=")
    conditions = " or ".join([f"{field}='{item}'" for item in items])

    # Construct final query
    if qid_condition:
        query = f"SELECT * from events where ({conditions}) AND ({qid_condition}) LAST {lookback}"
    else:
        query = f"SELECT * from events where ({conditions}) LAST {lookback}"
    return query


def generate_elastic_query(items: List[str], item_type: str, event_actions: Optional[List[str]] = None,
                           hash_type: str = "sha256", lookback: str = None) -> str:
    """
    Generate elastic query

    Args:
    - items (List[str]): A list of items
    - item_type (str): The type of item - must be one of 'ip', 'domain' or 'hash'
    - event_actions (Optional[List[str]]): Type of events to filter on (qid number equivalent)
    - hash_type (str): Hash type for hash queries (default: sha256)
    - lookback (str): Time range for the query

    Returns:
    - str: Elastic Query string
    """

    event_actions = event_actions or []

    field = get_elastic_field(item_type, hash_type)

    event_action_condition = build_conditions("event.action", event_actions, operator="or", wrap_values=True,
                                              quote_char="'", comparator=":")
    conditions = " or ".join([f"{field}:'{item}'" for item in items])

    # Construct final query
    if event_action_condition:
        query = f"({conditions}) and ({event_action_condition}) and @timestamp >= now-{lookback}"
    else:
        query = f"({conditions}) and @timestamp >= now-{lookback}"
    return query


def generate_defender_query(items: List[str], item_type: str, hash_type: str = "sha256", lookback: str = None) -> str:
    """
    Generate defender query

    Args:
    - items (List[str]): A list of items e.g., ip, domains, or hashes
    - item_type (str): 'ip', 'domain' or 'hash' to generate queries
    - hash_type (str): Hash type for hash queries (default: sha256)
    - lookback (str): Time range for the query

    Returns:
    - str: Defender Query string
    """

    config = get_defender_fields(item_type, hash_type)
    field = config["field"]
    table = config["table"]

    conditions = " or ".join([f"{field} contains '{item}'" for item in items])

    # Construct final query
    return f"{table} \n | where {conditions} \n | where Timestamp > ago({lookback})"


# =============================================================================
# MAIN QUERY GENERATION ORCHESTRATOR
# =============================================================================


def _validate_required_attr(args, attr_name):
    """
    Validate that a required attribute exists and has a value

    Args:
    - args (List[Any]): List of arguments
    - attr_name (str): Attribute name
    """

    if not getattr(args, attr_name):
        raise ValueError(f"{attr_name} is required")


def _validate_supported_value(args, attr_name, supported_values):
    """
    Validate that an attribute value is in the supported list.

    Args:
    - args (List[Any]): List of arguments
    - attr_name (str): Attribute name
    - supported_values (List[Any]): List of supported values
    """

    if getattr(args, attr_name).lower() not in supported_values:
        raise ValueError(
            f"Unsupported {attr_name}: Must be one of: {supported_values}")


def _validate_and_setup_args(args):
    """
    Validate arguments and setup defaults.

    Args:
    - args (List[Any]): List of arguments
    """

    # Validate required attributes
    _validate_required_attr(args, 'input')
    _validate_required_attr(args, 'lookback')
    _validate_required_attr(args, 'mode')
    _validate_required_attr(args, 'type')

    # Validate supported values
    _validate_supported_value(args, 'mode', SUPPORTED_MODES)
    _validate_supported_value(args, 'type', SUPPORTED_ITEM_TYPES)

    # Handle hash type validation and defaults
    if args.type.lower() == "hash":
        if not getattr(args, 'hash_type') or not args.hash_type:
            args.hash_type = DEFAULT_HASH_TYPE
        else:
            supported_hash_types = PLATFORM_HASH_TYPES.get(args.mode.lower(), SUPPORTED_HASH_TYPES)
            if args.hash_type.lower() not in supported_hash_types:
                raise ValueError(
                    f"Unsupported hash_type: {args.hash_type} for {args.mode}. "
                    f"Must be one of: {supported_hash_types}")


def _generate_platform_query(args, items, lookback):
    """
    Generate query based on the specified platform/mode.

    Args:
    - args (List[Any]): List of arguments
    - items (List[str]): A list of items e.g., ip, domains or hashes.
    - lookback (str): Time range for the query.
    """

    match args.mode.lower():
        case "aql":
            qid_list = getattr(args, 'qid', [])
            return generate_aql_query(items, args.type, qid_list, args.hash_type, lookback=lookback)
        case "es":
            event_actions = getattr(args, 'event_action', [])
            return generate_elastic_query(items, args.type, event_actions, args.hash_type, lookback=lookback)
        case "defender":
            return generate_defender_query(items, args.type, args.hash_type, lookback=lookback)
        case _:
            raise ValueError(f"Unsupported mode: {args.mode}. Supported modes: {SUPPORTED_MODES}")


def generate_query_from_args(args: Union[List[str], argparse.Namespace], parser=None) -> str:
    """
    Generate query from args

    Args:
    - args (Union[List[str], argparse.Namespace]): List of CLI-style arguments or parsed Namespace object
    - parser (Optional[ArgumentParser]): Parser instance to use if args is a list

    Returns:
    - str: The generated query string tailored to the chosen platform and input type
    """

    if parser is None:
        parser = create_parser()

    # Parse arguments if needed
    if isinstance(args, list):
        try:
            args = parser.parse_args(args)
        except SystemExit as e:
            raise ValueError(f"Failed to parse arguments: {e}")

    # Validate and setup arguments
    _validate_and_setup_args(args)

    # Extract items from input file
    items = extract_items(args.input)
    if not items:
        raise ValueError(f"No valid items found in input file: {args.input}")

    # Normalize lookback time
    try:
        lookback = normalize_lookback(args.lookback, args.mode)
        if lookback is None:
            raise ValueError(
                f"Invalid lookback format: '{args.lookback}'. "
                f"Valid formats: 5m, 10m, 30m, 1h, 3h, 12h, 1d")
    except Exception as e:
        raise ValueError(f"Failed to normalize lookback time: {e}")

    # Generate and return the query
    return _generate_platform_query(args, items, lookback)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def validate_query_parameters(item_type: str, mode: str, hash_type: str = "sha256") -> None:
    """
    Validate query parameters

    Args:
    - item_type (str): Type of item to validate
    - mode (str): Platform mode to validate
    - hash_type (str): Hash type to validate (default: sha256)
    """

    if item_type not in SUPPORTED_ITEM_TYPES:
        raise ValueError(f"Unsupported item_type: {item_type}. Must be one of: {SUPPORTED_ITEM_TYPES}")

    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode: {mode}. Must be one of: {SUPPORTED_MODES}")

    if item_type == "hash" and hash_type.lower() not in SUPPORTED_HASH_TYPES:
        raise ValueError(f"Unsupported hash_type: {hash_type}. Must be one of: {SUPPORTED_HASH_TYPES}")


def get_supported_combinations() -> Dict[str, List[str]]:
    """
    Get supported combinations

    Returns:
    - Dict[str, List[str]]: Dictionary of all supported configuration combinations
    """

    return {
        "modes": SUPPORTED_MODES,
        "item_types": SUPPORTED_ITEM_TYPES,
        "hash_types": SUPPORTED_HASH_TYPES
    }


def get_field_mapping_for_mode(mode: str) -> Dict:
    """
    Get field mappings

    Args:
    - mode (str): Platform mode (aql, es, defender)

    Returns:
    - Dict: Field mapping configuration for the specified mode
    """

    match mode.lower():
        case "aql":
            return AQL_FIELDS
        case "es":
            return ELASTIC_FIELDS
        case "defender":
            return DEFENDER_FIELDS
        case _:
            raise ValueError(f"Unsupported mode: {mode}. Must be one of: {SUPPORTED_MODES}")
