"""
Author: Olof Magnusson
Date: 2025-08-01

QRadar IOC Query Field Extractor

Script that reads a CSV/Excel file exported from QRadar and filters events for IOC analysis
Separates data into two categories:
1. IP/Domain events: Firewall Permit|Firewall Deny logs
2. Hash events: Malware|Exploit logs
"""

import argparse
import sys
import pandas as pd

from pathlib import Path
from typing import Tuple


def validate_input_file(filepath: str) -> Path:
    """
    Validate that input file exists and is readable.

    Args:
    - filepath: Path to input file

    Returns:
    - Path: Path to input file
    """

    file_path = Path(filepath)

    if not file_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {filepath}")

    if not file_path.is_file():
        raise ValueError(f"Path is not a file: {filepath}")

    # Usually we work with structured data in form of csv/xlsx files
    if file_path.suffix.lower() not in [".csv", ".xlsx"]:
        print(f"Warning: File extension '{file_path.suffix}' is in an incorrect format")

    return file_path


def create_output_directory(output_dir: str) -> Path:
    """
    Create output directory if it doesn't exist
    """

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    return output_path


def filter_dataframe(df: pd.DataFrame, pattern: str, description: str) -> pd.DataFrame:
    """
    Filter dataframe based on pattern matching across all columns

    Args:
    - df (pd.DataFrame): Dataframe to be filtered
    - pattern (str): Pattern to match column names
    - description (str): Description of the columns to be filtered

    Returns:
    - filtered (pd.DataFrame): Filtered dataframe
    """

    try:
        filtered_df = df[
            df.astype(str)
            .apply(lambda x: x.str.contains(pattern, case=False, na=False))
            .any(axis=1)
        ]
        print(f"Found {len(filtered_df)} rows matching '{pattern}' ({description})")
        return filtered_df
    except Exception as e:
        print(f"Error filtering dataframe with pattern '{pattern}': {e}")
        return pd.DataFrame()


def process_qradar_export(
    input_file: str,
    output_dir: str,
    ip_pattern: str,
    hash_pattern: str,
    output_prefix: str,
) -> Tuple[int, int]:
    """
    Process QRadar export CSV/Excel and create filtered outputs.

    Args:
    - input_file (str): Input file
    - output_dir (str): Output directory
    - ip_pattern (str): Pattern to match column names
    - hash_pattern (str): Pattern to match column names
    - output_prefix (str): Output prefix

    Returns:
        Tuple of (ip_domain_count, hash_count)
    """

    # Validate input
    input_path = validate_input_file(input_file)
    output_path = create_output_directory(output_dir)

    print(f"Processing file: {input_path}")
    print(f"Output directory: {output_path}")

    # Read CSV/Excel file
    try:
        if input_path.suffix.lower() == ".xlsx":
            df = pd.read_excel(input_path, engine="openpyxl")
            print(f"Loaded {len(df)} total rows from excel file")
        else:
            df = pd.read_csv(input_path)
            print(f"Loaded {len(df)} total rows from CSV file")
        if df.empty:
            raise RuntimeError("Warning: Input file is empty")
    except pd.errors.EmptyDataError:
        raise RuntimeError("Error: file is empty or invalid")
    except pd.errors.ParserError as e:
        raise RuntimeError(f"Error parsing file: {e}") from e
    except ImportError:
        raise RuntimeError(
            "Error: openpyxl library required for Excel files. Install with pip3 install openpyxl"
        )
    except Exception as e:
        raise (f"Unexpected error reading file: {e}")

    # Filter data
    ip_domain_df = filter_dataframe(df, ip_pattern, "IP/Domain events")
    hash_df = filter_dataframe(df, hash_pattern, "Hash events")

    # Generate output filenames
    ip_domain_output = output_path / f"{output_prefix}_ips_domains.csv"
    hash_output = output_path / f"{output_prefix}_hashes.csv"

    # Save filtered data
    try:
        if not ip_domain_df.empty:
            ip_domain_df.to_csv(ip_domain_output, index=False)
            print(f"Saved IP/Domain data to: {ip_domain_output}")
        else:
            print("Warning: No IP/Domain events found - no output file created")

        if not hash_df.empty:
            hash_df.to_csv(hash_output, index=False)
            print(f"Saved Hash data to: {hash_output}")
        else:
            print("Warning: No Hash events found - no output file created")
    except Exception as e:
        raise RuntimeError(f"Error saving output files: {e}")
    return len(ip_domain_df), len(hash_df)


def main():
    """
    Main driver
    """

    parser = argparse.ArgumentParser(
        description="Extract IOC query fields from QRadar CSV/Excel exports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i data_export.csv
  %(prog)s -i data_export.csv -o ./results/
  %(prog)s -i data_export.xlsx --ip-pattern "Firewall Allow|Firewall Block"
  %(prog)s -i data_export.csv --hash-pattern "Virus|Trojan|Malware"
        """,
    )

    # Required arguments
    parser.add_argument(
        "-i", "--input", required=True, help="Input CSV/Excel file exported from QRadar"
    )

    # Optional arguments
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Output directory for filtered CSV (default: current directory)",
    )

    parser.add_argument(
        "--ip-pattern",
        default="Firewall Permit|Firewall Deny",
        help='Pattern to match for IP/Domain events (default: "Firewall Permit|Firewall Deny")',
    )

    parser.add_argument(
        "--hash-pattern",
        default="Malware|Exploit",
        help='Pattern to match for Hash events (default: "Malware|Exploit")',
    )

    parser.add_argument(
        "--output-prefix",
        default="iocqueryfield",
        help='Prefix for output filenames (default: "iocqueryfield")',
    )

    args = parser.parse_args()

    try:
        # Process the file
        ip_count, hash_count = process_qradar_export(
            input_file=args.input,
            output_dir=args.output_dir,
            ip_pattern=args.ip_pattern,
            hash_pattern=args.hash_pattern,
            output_prefix=args.output_prefix,
        )
        # Summary
        print("=" * 50)
        print("PROCESSING COMPLETE")
        print(f"IP/Domain events: {ip_count}")
        print(f"Hash events: {hash_count}")
        print(f"Total events processed: {ip_count + hash_count}")
    except RuntimeError as e:
        print(
            f"Warning: No matching events found. Check your input data and patterns: {e}"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
