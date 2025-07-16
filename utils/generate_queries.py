"""
A simple program that generates a search query based on a given list

Author: Olof Magnusson
Date: 2025-07-02
"""

import argparse

from typing import List, Optional, Union, Dict

from utils.configuration import create_parser, extract_items, normalize_lookback
from utils.configuration import build_conditions

"""
Generate queries based on provided platform 'aql', 'elastic' or 'defender
"""

# =============================================================================
# PLATFORM FIELD MAPPINGS AND CONSTANTS
# =============================================================================

# Supported types and formats
SUPPORTED_HASH_TYPES = ["md5", "sha1", "sha256", "filehash"]
SUPPORTED_ITEM_TYPES = ["ip", "domain", "hash"]
SUPPORTED_MODES = ["aql", "es", "defender"]

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

# Elastic Search Platform Field Mappings
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
DEFENDER_CONFIG = {
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
# FIELD MAPPING HELPER FUNCTIONS
# =============================================================================

def get_aql_field(item_type: str, hash_type: str = "sha256") -> str:
    """
    Get AQL field

    Args:
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items (default: sha256)

    Returns:
    - str: AQL field name
    """
    
    if item_type not in SUPPORTED_ITEM_TYPES:
        raise ValueError(f"Unsupported item_type: {item_type}. Must be one of: {SUPPORTED_ITEM_TYPES}")
    
    if item_type == "hash":
        if hash_type.lower() not in SUPPORTED_HASH_TYPES:
            raise ValueError(f"Unsupported hash_type: {hash_type}. Must be one of: {SUPPORTED_HASH_TYPES}")
        return AQL_FIELDS["hash"][hash_type.lower()]
    
    return AQL_FIELDS[item_type]

def get_elastic_field(item_type: str, hash_type: str = "sha256") -> str:
    """
    Get Elastic field

    Args:
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items (default: sha256)

    Returns:
    - str: Elastic field name
    """

    if item_type not in SUPPORTED_ITEM_TYPES:
        raise ValueError(f"Unsupported item_type: {item_type}. Must be one of: {SUPPORTED_ITEM_TYPES}")
    
    if item_type == "hash":
        if hash_type.lower() not in SUPPORTED_HASH_TYPES:
            raise ValueError(f"Unsupported hash_type: {hash_type}. Must be one of: {SUPPORTED_HASH_TYPES}")
        return ELASTIC_FIELDS["hash"][hash_type.lower()]
    
    return ELASTIC_FIELDS[item_type]

def get_defender_config(item_type: str, hash_type: str = "sha256") -> Dict[str, str]:
    """
    Get Defender config

    Args:
    - item_type (str): Type of item (ip, domain, hash)
    - hash_type (str): Hash type for hash items (default: sha256)

    Returns:
    - Dict[str, str]: Dictionary with 'field' and 'table' keys
    """

    if item_type not in SUPPORTED_ITEM_TYPES:
        raise ValueError(f"Unsupported item_type: {item_type}. Must be one of: {SUPPORTED_ITEM_TYPES}")
    
    config = DEFENDER_CONFIG[item_type].copy()
    
    if item_type == "hash":
        if hash_type.lower() not in SUPPORTED_HASH_TYPES:
            raise ValueError(f"Unsupported hash_type: {hash_type}. Must be one of: {SUPPORTED_HASH_TYPES}")
        config["field"] = config["fields"][hash_type.lower()]
        del config["fields"]  # Clean up the nested structure
    
    return config

# =============================================================================
# QUERY GENERATION FUNCTIONS
# =============================================================================

def generate_aql_query(items: List[str], item_type: str, qids: Optional[List[int]] = None, hash_type: str = "sha256", lookback: str = None) -> str:
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
        query = f"SELECT * from events where {conditions} AND ({qid_condition}) LAST {lookback}"
    else:
        query = f"SELECT * from events where ({conditions}) LAST {lookback}"

    return query

def generate_elastic_query(items: List[str], item_type: str, event_actions: Optional[List[str]] = None, hash_type: str = "sha256", lookback: str = None) -> str:
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
    
    event_action_condition = build_conditions("event.action", event_actions, operator="or", wrap_values=True, quote_char="'", comparator=":")
    conditions = " or ".join([f"{field}:'{item}'" for item in items])

    # Construct final query
    if event_action_condition:
        query = f"{conditions} and ({event_action_condition}) and @timestamp >= now-{lookback}"
    else:
        query = f"{conditions} and @timestamp >= now-{lookback}"

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

    config = get_defender_config(item_type, hash_type)
    field = config["field"]
    table = config["table"]
    
    conditions = " or ".join([f"{field} contains '{item}'" for item in items])
    
    # Construct final query
    return f"{table} \n | where {conditions} \n | where Timestamp > ago({lookback})"

# =============================================================================
# MAIN QUERY GENERATION ORCHESTRATOR
# =============================================================================

def generate_query_from_args(args: Union[List[str], argparse.Namespace], parser = None) -> str:
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
    
    # If args is a list of command arguments, parse them
    if isinstance(args, list):
        try:
            args = parser.parse_args(args)
        except SystemExit as e:
            raise ValueError(f"Failed to parse arguments: {e}")
    
    # Validate required arguments
    if not hasattr(args, 'input') or not args.input:
        raise ValueError("Input file is required")
    
    if not hasattr(args, 'lookback') or not args.lookback:
        raise ValueError("Lookback time is required")
    
    if not hasattr(args, 'mode') or not args.mode:
        raise ValueError("Mode is required")
    
    if not hasattr(args, 'type') or not args.type:
        raise ValueError("Type is required")
    
    # Validate mode and type values
    if args.mode.lower() not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode: {args.mode}. Must be one of: {SUPPORTED_MODES}")
    
    if args.type.lower() not in SUPPORTED_ITEM_TYPES:
        raise ValueError(f"Unsupported type: {args.type}. Must be one of: {SUPPORTED_ITEM_TYPES}")
    
    # Validate hash type if needed
    if args.type.lower() == "hash":
        if not hasattr(args, 'hash_type') or not args.hash_type:
            args.hash_type = "sha256"  # Default
        elif args.hash_type.lower() not in SUPPORTED_HASH_TYPES:
            raise ValueError(f"Unsupported hash_type: {args.hash_type}. Must be one of: {SUPPORTED_HASH_TYPES}")
    
    # Extract items from input file
    items = extract_items(args.input)
    if not items:
        raise ValueError(f"No valid items found in input file: {args.input}")
    
    # Normalize lookback time
    try:
        lookback = normalize_lookback(args.lookback, args.mode)
        if lookback is None:
            raise ValueError(f"Invalid lookback format: '{args.lookback}'. Valid formats: 5m, 10m, 30m, 1h, 3h, 12h, 1d")
    except Exception as e:
        raise ValueError(f"Failed to normalize lookback time: {e}")
    
    # Generate query based on mode
    try:
        match args.mode.lower():
            case "aql":
                if not hasattr(args, 'qid'):
                    raise ValueError("QID is required for AQL mode")
                return generate_aql_query(items, args.type, args.qid, args.hash_type, lookback=lookback)
            case "es":
                if not hasattr(args, 'event_action'):
                    raise ValueError("Event action is required for ES mode")
                return generate_elastic_query(items, args.type, args.event_action, args.hash_type, lookback=lookback)
            case "defender":
                return generate_defender_query(items, args.type, args.hash_type, lookback=lookback)
            case _:
                raise ValueError(f"Unsupported mode: {args.mode}. Supported modes: {SUPPORTED_MODES}")    

    except Exception as e:
        raise ValueError(f"Failed to generate {args.mode} query: {e}")

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
    
    try:
        match mode.lower():
            case "aql":
                return AQL_FIELDS
            case "es":
                return ELASTIC_FIELDS
            case "defender":
                return DEFENDER_CONFIG
            case _:
                raise ValueError(f"Unsupported mode: {mode}. Must be one of: {SUPPORTED_MODES}")
    except Exception as e:
        raise ValueError(f"Failed to get field mappings for {mode} mode: {e}")
        
