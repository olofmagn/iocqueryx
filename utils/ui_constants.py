import logging

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

# Window Configuration
DEFAULT_WINDOW_WIDTH = 500
DEFAULT_WINDOW_HEIGHT = 400
DEFAULT_OUTPUT_HEIGHT = 10
WINDOW_TITLE = "IocQueryX - IOC Hunting Query Generator"
WINDOW_PADDING = 10
FRAME_SIZE_MINIMUM = 100

# Default Values
DEFAULT_MODE = "aql"
DEFAULT_TYPE = "ip"
DEFAULT_TIME_RANGE_INDEX = 1  # "10 MINUTES"

# Widget Styling Constants
DEFAULT_PADDING = 10
WIDGET_PADDING_X = 2
WIDGET_PADDING_Y = 2
TIME_ENTRY_WIDTH = 15
ARROW_BUTTON_WIDTH = 2
ARROW_BUTTON_PADDING = (6, 0)

# Grid Positioning Constants
GRID_STICKY_W = "w"
GRID_STICKY_EW = "ew"
GRID_STICKY_NSEW = "nsew"
GRID_STICKY_E = "e"

# Time Range Configuration
TIME_RANGES = [
    ("5m", "5 MINUTES"),
    ("10m", "10 MINUTES"),
    ("30m", "30 MINUTES"),
    ("1h", "1 HOUR"),
    ("3h", "3 HOURS"),
    ("12h", "12 HOURS"),
    ("1d", "1 DAY"),
]

# Mode Configuration
MODE_CONFIGS = {
    "aql": {
        "info": "Using AQL Search query mode",
        "label": "QID:",
        "show_qid": True,
        "show_ea": False,
    },
    "es": {
        "info": "Using Elastic Search query mode",
        "label": "EA:",
        "show_qid": False,
        "show_ea": True,
    },
    "defender": {
        "info": "Using Defender Search query mode",
        "label": "",
        "show_qid": False,
        "show_ea": False,
        "show_projection": True,
    },
}

# UI Text Constants
COPYRIGHT_TEXT = "© 2025 olofmagn"
COPYRIGHT_FONT = ("Segoe UI", 8, "italic")
COPYRIGHT_COLOR = "gray50"

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

# Application Configuration
DEFAULT_LOGGER_NAME = "IocQueryx"
DEFAULT_LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DEFAULT_ENCODING = "utf-8"

# Supported Values
SUPPORTED_MODES = ["aql", "es", "defender"]
SUPPORTED_TYPES = ["ip", "domain", "hash"]
SUPPORTED_HASH_TYPES = ["md5", "sha1", "sha256", "filehash"]

SUPPORTED_ITEM_TYPES = ["ip", "domain", "hash"]

# Hash Type Configuration
STANDARD_HASH_TYPES = ["md5", "sha1", "sha256"]
AQL_HASH_TYPES = STANDARD_HASH_TYPES + ["filehash"]
DEFAULT_HASH_TYPE = "sha256"

# Platform-Specific Hash Types
PLATFORM_HASH_TYPES = {
    "aql": AQL_HASH_TYPES,
    "es": STANDARD_HASH_TYPES,
    "defender": STANDARD_HASH_TYPES,
}

# Time Unit Mappings
TIME_UNIT_PATTERNS = {
    "minutes": ["minute", "minutes", "min", "m"],
    "hours": ["hour", "hours", "h"],
    "days": ["day", "days", "d"],
}

# Platform-specific time formats
DEFENDER_ES_PLATFORMS = ["defender", "es"]
AQL_PLATFORM = "aql"

# Regex Patterns
LOOKBACK_PATTERN = r"(\d+)\s*(minutes?|hours?|days?|min|m|h|d)"

# File Processing Configuration
CSV_DELIMITER = ","
FIRST_COLUMN_INDEX = 0
