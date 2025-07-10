"""
A simple program that generates a search query based on a given list.

Author: Olof Magnusson
Date: 2025-07-02
"""

from typing import List, Optional

from utils.utility import create_parser, extract_items, normalize_lookback
from utils.utility import build_conditions

"""
Generate queries based on provided platform 'aql', 'elastic' or 'defender
"""

def generate_aql_query(items: List[str], item_type: str, qids: Optional[List[int]] = None, hash_type: str = "sha256", lookback: str = None) -> str:
    """
    Generate an AQL query filtering by IP or domain and qid.

    Args:
    - items (List[str]): A list of items, e.g., ip, domains or hashes.
    - item_type (str): The type of item - must be one of 'ip', 'domain' or 'hash' to generate queries.
    - qid (int): Optional QID number for filtering.

    Returns:
    - str: AQL query string
    """

    qids = qids if qids else []

    match item_type:
        case "ip":
            field = "source ip"
        case "domain":
            field = "url domain"
        case "hash":
            aql_field_map: Dict[str, str] = {
                "md5": "md5 hash",
                "sha1": "sha1 hash",
                "sha256": "sha256 hash"
            }
            field = aql_field_map.get(hash_type.lower())
            if not field:
                raise ValueError("Unsupported hash type for AQL")
        case _:
            raise ValueError(
                "Unsupported item_type. Must be 'ip', 'domain' or 'file hash'")

    qid_condition = build_conditions(
        "qid", qids, operator="or", wrap_values=True, comparator="=")
    conditions = " or ".join([f"{field}='{item}'" for item in items])

    if qid_condition:
        query = f"SELECT * from events where {conditions} AND ({qid_condition}) LAST {lookback}"
    else:
        query = f"SELECT * from events where ({conditions}) LAST {lookback}"

    return query


def generate_elastic_query(items: List[str], item_type: str, event_actions: Optional[List[str]] = None, hash_type: str = "sha256", lookback: str = None) -> str:
    """
    Args:
    - items (List[str]): A list of items.
    - event_actions (List[str]): Type of events to filter on (qid number equivalent).

    Returns:
    - str: Elastic Query string.
    """

    event_actions = event_actions if event_actions else []

    match item_type:
        case "ip":
            field = "source.ip"
        case "domain":
            field = "url.domain"
        case "hash":
            elastic_field_map: Dict[str, str] = {
                "md5": "file.hash.md5",
                "sha1": "file.hash.sha1",
                "sha256": "file.hash.sha256"
            }
            field = elastic_field_map.get(hash_type.lower())
            if not field:
                raise ValueError("Unsupported hash type for elastic")
        case _:
            raise ValueError(
                "Unsupported item_type. Must be 'ip', 'domain' or 'file hash'")

    event_action_condition = build_conditions("event.action", event_actions, operator="or", wrap_values=True, quote_char="'", comparator=":")
    conditions = " or ".join([f"{field}:'{item}'" for item in items])

    if event_action_condition:
        query = f"{conditions} and ({event_action_condition}) and @timestamp >= now-{lookback}"
    else:
        query = f"{conditions} and @timestamp >= now-{lookback}"

    return query


def generate_defender_query(items: List[str], item_type: str, hash_type: str = "sha256", lookback: str = None) -> str:
    """
    Args:
    - items (List[str]): A list of items e.g., ip, domains, or hashes
    - item_type (str): 'ip', 'domain' or 'hash' to generate queries

    Returns:
    - str: Defender Query string
    """

    match item_type:
        case "ip":
            field = "RemoteIP"
            table = "DeviceNetworkEvents"
        case "domain":
            field = "RemoteUrl"
            table = "DeviceNetworkEvents"
        case "hash":
            table = "DeviceFileEvents"
            defender_field_map: Dict[str, str] = {
                "md5": "InitiatingProcessMD5",
                "sha1": "InitiatingProcessSHA1",
                "sha256": "SHA256"
            }
            field = defender_field_map.get(hash_type.lower())
            if not field:
                raise ValueError("Unsupported hash type for Defender")
        case _:
            raise ValueError(
                "Unsupported item_type. Must be 'ip', 'domain', or 'hash'")

    conditions = " or ".join([f"{field} contains '{item}'" for item in items])
    return f"{table}\n | where {conditions} \n | where Timestamp > ago({lookback})"

def generate_query_from_args(args: str, parser = None) -> str:
    """
    Parses the given arguments and generates a threat hunting query

    Args:
    args (str): List of CLI-style arguments or an already parsed argparse.Namespace object

    Returns:
    - str: The generated query string tailoreed to the chosen platform and input type.
    """

    if parser is None:
        parser = create_parser()
    
    # If args is a list of command arguments
    if isinstance(args, list):
        args = parser.parse_args(args)

    items = extract_items(args.input)
    lookback = normalize_lookback(args.lookback, args.mode)

    match args.mode:
        case "aql":
            return generate_aql_query(items, args.type, args.qid, args.hash_type,lookback=lookback)
        case "es":
            return generate_elastic_query(items, args.type, args.event_action, args.hash_type, lookback=lookback)
        case "defender":
            return generate_defender_query(items, args.type, args.hash_type, lookback=lookback)
        case _:
            return "aql" # return defender as some kind of default
