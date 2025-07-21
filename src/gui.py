"""
A simple program that generates a search query based on a given list to identify first point of contact

Author: Olof Magnusson
Date: 2025-07-02
"""

import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from typing import Optional, List, Tuple

from utils.generate_queries import generate_query_from_args

from utils.configuration import (
    get_logger,
    get_supported_hash_types,
    normalize_lookback,
)

from utils.ui_constants import (
    DEFAULT_WINDOW_WIDTH,
    DEFAULT_WINDOW_HEIGHT,
    DEFAULT_OUTPUT_HEIGHT,
    DEFAULT_HASH_TYPE,
    DEFAULT_TYPE,
    DEFAULT_TIME_RANGE_INDEX,
    DEFAULT_MODE,
    DEFAULT_PADDING,
    FRAME_SIZE_MINIMUM,
    WINDOW_TITLE,
    WINDOW_PADDING,
    WIDGET_PADDING_X,
    WIDGET_PADDING_Y,
    TIME_ENTRY_WIDTH,
    ARROW_BUTTON_WIDTH,
    ARROW_BUTTON_PADDING,
    GRID_STICKY_W,
    GRID_STICKY_EW,
    GRID_STICKY_NSEW,
    GRID_STICKY_E,
    TIME_RANGES,
    MODE_CONFIGS,
    COPYRIGHT_TEXT,
    COPYRIGHT_FONT,
    COPYRIGHT_COLOR,
    SUPPORTED_MODES,
    SUPPORTED_TYPES,
    SUPPORTED_HASH_TYPES,
)


# =============================================================================
# TIME RANGE UTILITIES
# =============================================================================

def get_display_values() -> List[str]:
    """
    Get display values

    Returns:
    - List[str]: List of display values for time ranges
    """

    return [display for _, display in TIME_RANGES]


def get_default_time_display() -> str:
    """
    Get default time range display value

    Returns:
    - str: Default time range display value
    """

    return get_display_values()[DEFAULT_TIME_RANGE_INDEX]


def cycle_time_range_value(current_value: str, direction: int, display_values: List[str]) -> str:
    """
    Cycle time range value

    Args:
    - current_value (str): Current time range value
    - direction (int): Direction to cycle (-1 or 1)
    - display_values (List[str]): Available display values

    Returns:
    - str: New time range value
    """

    try:
        current_idx = display_values.index(current_value)
    except ValueError:
        current_idx = DEFAULT_TIME_RANGE_INDEX

    new_idx = (current_idx + direction) % len(display_values)

    return display_values[new_idx]


# =============================================================================
# VALIDATION UTILITIES
# =============================================================================

def validate_comma_separated_items(raw_input: str, is_numeric: bool = False) -> Tuple[bool, List[str], str]:
    """
    Validate comma seperated items

    Args:
    - raw_input (str): Raw comma-separated input
    - is_numeric (bool): Whether items should be numeric
    
    Returns:
    - Tuple[bool, List[str], str]: (is_valid, items, error_message)
    """

    if not raw_input.strip():
        return True, [], ""

    items = [item.strip() for item in raw_input.split(",") if item.strip()]

    if not items:
        return False, [], "contains no valid entries."

    if is_numeric:
        invalid_items = [item for item in items if not item.isdigit()]
        if invalid_items:
            invalid_list = "', '".join(invalid_items)
            return False, [], f"contains invalid integers: '{invalid_list}'"

    return True, items, ""


def validate_file_input(file_path: str) -> bool:
    """
    Validate file input

    Args:
    - file_path (str): File path to validate

    Returns:
    - bool: True if valid file path
    """

    return bool(file_path and file_path.strip())


# =============================================================================
# ERROR HANDLING UTILITIES
# =============================================================================

def show_error_message(title: str, message: str) -> None:
    """
    Show error messages

    Args:
    - title (str): Error dialog title
    - message (str): Error message
    """

    messagebox.showerror(title, message)


def show_info_message(title: str, message: str) -> None:
    """
    Show info message

    Args:
    - title (str): Info dialog title
    - message (str): Info message
    """

    messagebox.showinfo(title, message)


def log_error_message(logger, message: str) -> None:
    """
    Show log error message

    Args:
    - logger: Logger instance
    - message (str): Message to log
    """

    logger.error(message)


# =============================================================================
# QUERY ARGUMENT UTILITIES
# =============================================================================

def build_base_query_arguments(input_file: str, mode: str, type_val: str, hash_type: str, lookback: str) -> List[str]:
    """
    Build base query arguments

    Args:
    - input_file (str): Input file path
    - mode (str): Query mode
    - type_val (str): Query type
    - hash_type (str): Hash type
    - lookback (str): Lookback time

    Returns:
    - List[str]: Base arguments list
    """

    return [
        "-i", input_file,
        "-m", mode,
        "-t", type_val,
        "-ht", hash_type,
        "-l", lookback
    ]


def hide_entry_widget(widget) -> None:
    """
    Hide entry widget if visible.

    Args:
    - widget: Widget to hide
    """

    if widget.winfo_ismapped():
        widget.grid_remove()


def extend_arguments_for_mode(base_args: List[str], mode: str, qids: List[str] = None, eas: List[str] = None) -> List[
    str]:
    """
    Extend arguments for mode

    Args:
    - base_args (List[str]): Base arguments
    - mode (str): Query mode
    - qids (List[str]): QID values for AQL mode
    - eas (List[str]): EA values for ES mode

    Returns:
    - List[str]: Extended arguments
    """

    args = base_args.copy()
    match mode:
        case "aql":
            if qids:
                args.extend(["-q"] + qids)
        case "es":
            if eas:
                args.extend(["-ea"] + eas)
    return args


# =============================================================================
# MAIN GUI CLASS
# =============================================================================

class QueryGeneratorGUI:
    def __init__(self, root) -> None:
        """
        Args:
        - root: Tkinter root window
        """

        # Initialize core attributes
        self.logger = get_logger()
        self.saved_qid_input = ""
        self.saved_ea_input = ""

        # Window size constants 
        self.MAX_WIDTH = DEFAULT_WINDOW_WIDTH
        self.MAX_HEIGHT = DEFAULT_WINDOW_HEIGHT
        self.OUTPUT_HEIGHT = DEFAULT_OUTPUT_HEIGHT

        # Time ranges 
        self.time_ranges = TIME_RANGES
        self.MODE_CONFIGS = MODE_CONFIGS
        self.display_values = get_display_values()

        # Setup window
        self.root = root
        self.root.title(WINDOW_TITLE)
        self.root.minsize(self.MAX_HEIGHT, self.MAX_WIDTH)
        self.root.resizable(True, True)

        self.frame = ttk.Frame(root, padding=WINDOW_PADDING)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Initialize GUI
        self._create_widgets()
        self._setup_trace_callbacks()
        self._update_mode_visibility()
        self._update_hash_type_visibility()

    # =========================================================================
    # PROPERTY METHODS (CACHED ACCESS)
    # =========================================================================

    @property
    def current_mode(self) -> str:
        """
        Current mode

        Returns:
        - str: Current mode in lowercase
        """

        return self.mode_var.get().lower()

    @property
    def current_type(self) -> str:
        """
        Current type

        Returns:
        - str: Current type selection
        """

        return self.type_var.get()

    @property
    def current_hash_type(self) -> str:
        """
        Current hash type

        Returns:
        - str: Current hash type selection
        """

        return self.hash_type_var.get()

    @property
    def current_lookback(self) -> str:
        """
        Current lookback

        Returns:
        - str: Current lookback value
        """

        return self.lookback_var.get()

    # =========================================================================
    # WIDGET CREATION METHODS
    # =========================================================================

    def _create_widgets(self) -> None:
        """
        Create widgets
        """

        self.frame.columnconfigure(0, weight=0, minsize=FRAME_SIZE_MINIMUM)  # Labels column
        self.frame.columnconfigure(1, weight=1)  # Controls column
        self.frame.rowconfigure(9, weight=1)

        # === Input file ===
        ttk.Label(self.frame, text="Input File:").grid(row=0, column=0, sticky=GRID_STICKY_W,
                                                       padx=(WIDGET_PADDING_X, DEFAULT_PADDING),
                                                       pady=WIDGET_PADDING_Y)
        self.input_entry_var = ttk.Entry(self.frame)
        self.input_entry_var.grid(row=0, column=1, sticky=GRID_STICKY_NSEW, padx=WIDGET_PADDING_X,
                                  pady=WIDGET_PADDING_Y)
        ttk.Button(self.frame, text="Browse", command=self._browse_file).grid(row=0, column=2, sticky=GRID_STICKY_E,
                                                                              padx=WIDGET_PADDING_X,
                                                                              pady=WIDGET_PADDING_Y)

        # === Mode selection ===
        ttk.Label(self.frame, text="Mode:").grid(row=1, column=0, sticky=GRID_STICKY_NSEW,
                                                 padx=(WIDGET_PADDING_X, DEFAULT_PADDING),
                                                 pady=WIDGET_PADDING_Y)
        self.mode_var = tk.StringVar(value=DEFAULT_MODE)
        self.mode_combobox = ttk.Combobox(self.frame,
                                          textvariable=self.mode_var,
                                          values=SUPPORTED_MODES,
                                          state="readonly")
        self.mode_combobox.grid(row=1, column=1, columnspan=2, sticky=GRID_STICKY_NSEW, padx=WIDGET_PADDING_X,
                                pady=WIDGET_PADDING_Y)

        # === Type selection ===
        ttk.Label(self.frame, text="Type:").grid(row=2, column=0, sticky=GRID_STICKY_NSEW,
                                                 padx=(WIDGET_PADDING_X, DEFAULT_PADDING),
                                                 pady=WIDGET_PADDING_Y)
        self.type_var = tk.StringVar(value=DEFAULT_TYPE)
        self.type_combobox = ttk.Combobox(self.frame,
                                          textvariable=self.type_var,
                                          values=SUPPORTED_TYPES,
                                          state="readonly")
        self.type_combobox.grid(row=2, column=1, columnspan=2, sticky=GRID_STICKY_NSEW, padx=WIDGET_PADDING_X,
                                pady=WIDGET_PADDING_Y)

        # === Hash type ===
        self.hash_type_label = ttk.Label(self.frame, text="Hash Type:")
        self.hash_type_label.grid(row=3, column=0, sticky=GRID_STICKY_NSEW,
                                  padx=(WIDGET_PADDING_X, DEFAULT_PADDING),
                                  pady=WIDGET_PADDING_Y)
        self.hash_type_var = tk.StringVar(value=DEFAULT_HASH_TYPE)
        self.hash_type_combobox = ttk.Combobox(self.frame,
                                               textvariable=self.hash_type_var,
                                               values=SUPPORTED_HASH_TYPES,
                                               state="readonly")
        self.hash_type_combobox.grid(row=3, column=1, columnspan=2, sticky=GRID_STICKY_NSEW, padx=WIDGET_PADDING_X,
                                     pady=WIDGET_PADDING_Y)

        # === QID/EA ===
        self.input_label = ttk.Label(self.frame, text="QID:")
        self.input_label.grid(row=4, column=0, sticky=GRID_STICKY_W,
                              padx=(WIDGET_PADDING_X, DEFAULT_PADDING),
                              pady=WIDGET_PADDING_Y)

        self.mode_entry_container = ttk.Frame(self.frame)
        self.mode_entry_container.grid(row=4, column=1, columnspan=2, sticky=GRID_STICKY_EW,
                                       padx=WIDGET_PADDING_X, pady=WIDGET_PADDING_Y)
        self.mode_entry_container.columnconfigure(0, weight=1)

        self.qid_entry = ttk.Entry(self.mode_entry_container)
        self.ea_entry = ttk.Entry(self.mode_entry_container)
        self.qid_entry.grid(row=0, column=0, sticky=GRID_STICKY_EW)

        # === Time range ===
        ttk.Label(self.frame, text="Time Range:").grid(row=5, column=0, sticky=GRID_STICKY_W,
                                                       padx=(WIDGET_PADDING_X, DEFAULT_PADDING),
                                                       pady=WIDGET_PADDING_Y)
        time_frame = ttk.Frame(self.frame)
        time_frame.grid(row=5, column=1, columnspan=2, sticky=GRID_STICKY_W, padx=WIDGET_PADDING_X,
                        pady=WIDGET_PADDING_Y)
        self.lookback_var = tk.StringVar(value=self.display_values[DEFAULT_TIME_RANGE_INDEX])
        self.time_entry = ttk.Entry(time_frame, textvariable=self.lookback_var, width=TIME_ENTRY_WIDTH)
        self.time_entry.pack(side="left")

        # Arrow buttons
        self.btn_time_prev = ttk.Button(time_frame, text="❮", style="Arrow.TButton",
                                        padding=ARROW_BUTTON_PADDING, width=ARROW_BUTTON_WIDTH,
                                        command=lambda: self._change_time_range(-1))
        self.btn_time_prev.pack(side="left", padx=1)
        self.btn_time_next = ttk.Button(time_frame, text="❯", style="Arrow.TButton",
                                        padding=ARROW_BUTTON_PADDING, width=ARROW_BUTTON_WIDTH,
                                        command=lambda: self._change_time_range(1))
        self.btn_time_next.pack(side="right", padx=1)

        # === Spacer for visual separation ===
        self.spacer_frame = ttk.Frame(self.frame, height=1)
        self.spacer_frame.grid(row=6, column=0, columnspan=3, pady=(15, 10))

        # === Apply field selection checkbox ===
        self.include_post_pipeline_var = tk.BooleanVar(value=False)
        self.checkbox = tk.Checkbutton(
            self.frame,
            text="Apply field selection",
            variable=self.include_post_pipeline_var
        )
        self.checkbox.grid(row=7, column=0, columnspan=3,
                           padx=WIDGET_PADDING_X, pady=(5, 10))

        # === Generate query ===
        ttk.Button(self.frame, text="Generate Query", command=self._generate_query).grid(row=8, column=0, columnspan=3,
                                                                                         pady=(5, 10),
                                                                                         padx=WIDGET_PADDING_X)

        # === Output text ===
        self.output_text = ScrolledText(self.frame, height=self.OUTPUT_HEIGHT, wrap=tk.WORD)
        self.output_text.grid(row=9, column=0, columnspan=3, sticky=GRID_STICKY_NSEW, pady=5, padx=WIDGET_PADDING_X)

        # === Copy to Clipboard ===
        ttk.Button(self.frame, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=10, column=0,
                                                                                              columnspan=3, pady=5,
                                                                                              sticky=GRID_STICKY_NSEW,
                                                                                              padx=WIDGET_PADDING_X)

        # === Separator ===
        separator = ttk.Separator(self.frame, orient='horizontal')
        separator.grid(row=11, column=0, columnspan=3, sticky='nsew', pady=(10, 5))

        # === Platform info label ===
        self.platform_info_label = ttk.Label(self.frame, text="")
        self.platform_info_label.grid(row=12, column=0, columnspan=3, sticky=GRID_STICKY_NSEW, pady=(0, 2), padx=5)
        self.platform_info_label.config(anchor="center", justify="center")

        # === Copyright label ===
        self.copyright_label = ttk.Label(
            self.frame, text=COPYRIGHT_TEXT, font=COPYRIGHT_FONT, foreground=COPYRIGHT_COLOR
        )
        self.copyright_label.grid(row=13, column=2, sticky=GRID_STICKY_E, pady=(0, 10), padx=5)

    # =========================================================================
    # EVENT HANDLING METHODS
    # =========================================================================

    def _setup_trace_callbacks(self) -> None:
        """
        Setup trace callbacks
        """

        self.mode_var.trace_add("write", lambda *args: self._update_mode_visibility())
        self.type_var.trace_add("write", lambda *args: self._update_hash_type_visibility())

    def _browse_file(self) -> None:
        """
        Browse fields
        """

        try:
            file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
            if file_path:
                self.input_entry_var.delete(0, tk.END)
                self.input_entry_var.insert(0, file_path)
        except Exception as e:
            show_error_message("Error", f"Failed to load file: {e}")
            sys.exit(1)

    def _change_time_range(self, direction: int) -> None:
        """
        Change time range

        Args:
        - direction (int): Direction to navigate (-1 for prev, 1 for next)
        """

        new_value = cycle_time_range_value(self.current_lookback, direction, self.display_values)
        self.lookback_var.set(new_value)
        self.logger.info("Time range changed")

    # =========================================================================
    # INPUT VALIDATION METHODS
    # =========================================================================

    def _validate_inputs(self) -> bool:
        """
        Validate inputs

        Returns:
        - bool: True if inputs are valid
        """

        if not validate_file_input(self.input_entry_var.get()):
            self._show_validation_error("Please select an input file.")
            return False
        return True

    def _validate_time_range(self) -> bool:
        """
        Validate time range

        Returns:
        - bool: True if time range is valid
        """

        duration = normalize_lookback(self.current_lookback, self.current_mode)
        if duration is None:
            self._show_validation_error("Invalid time range")
            return False
        return True

    def _validate_comma_separated_input(self, raw_input: str, label: str, is_numeric: bool = False) -> Optional[
        List[str]]:
        """
        Validate comma seperated input

        Args:
        - raw_input (str): Comma-separated input string to validate
        - label (str): Field label for error message
        - is_numeric (bool): Whether to validate items as numeric values

        Returns:
        - Optional[List[str]]: List of valid items or None if validation fails
        """

        is_valid, items, error_msg = validate_comma_separated_items(raw_input, is_numeric)

        if not is_valid:
            self._show_validation_error(f"{label} {error_msg}")
            return None

        return items

    def _show_validation_error(self, message: str) -> None:
        """
        Show validation error

        Args:
        - message (str): Error message to display and log
        """

        show_error_message("Invalid input", message)
        log_error_message(self.logger, message)

    # =========================================================================
    # QUERY GENERATION METHODS
    # =========================================================================

    def _build_base_args(self) -> List[str]:
        """
        Build base args

        Returns:
        - List[str]: Base arguments list for query generation
        """

        return build_base_query_arguments(
            self.input_entry_var.get(),
            self.current_mode,
            self.current_type,
            self.current_hash_type,
            self.current_lookback
        )

    def _build_mode_specific_args(self, base_args: List[str]) -> Optional[List[str]]:
        """
        Build mode specific args

        Args:
        - base_args (List[str]): Base arguments to extend with mode-specific parameters

        Returns:
        - Optional[List[str]]: Complete arguments list or None if validation fails
        """

        match self.current_mode:
            case "aql":
                qids = self._validate_comma_separated_input(self.qid_entry.get(), "QID", is_numeric=True)
                if qids is None:
                    return None
                return extend_arguments_for_mode(base_args, self.current_mode, qids=qids)
            case "es":
                eas = self._validate_comma_separated_input(self.ea_entry.get(), "EA")
                if eas is None:
                    return None
                return extend_arguments_for_mode(base_args, self.current_mode, eas=eas)
            case "defender":
                if hasattr(self, 'include_post_pipeline_var') and self.include_post_pipeline_var.get():
                    return base_args + ["-p"]  # projection flag
                return base_args
            case _:
                return base_args

    def _display_query(self, query: str) -> None:
        """
        Display query
    
        Args:
        - query (str): The generated query string to display
        """

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, query)

    def _handle_error(self, title: str, message: str, exit_on_error: bool = False) -> None:
        """
        Handle errors

        Args:
        - title (str): Error dialog title
        - message (str): Error message to display and log
        - exit_on_error (bool): Whether to exit application on error
        """

        show_error_message(title, message)
        log_error_message(self.logger, f"{title}: {message}")
        if exit_on_error:
            sys.exit(1)

    def _generate_query(self) -> None:
        """
        Generate query
        """

        try:
            # Validate inputs
            if not self._validate_inputs():
                return

            # Validate time range
            if not self._validate_time_range():
                return

            # Build base arguments
            base_args = self._build_base_args()

            # Add mode-specific arguments
            final_args = self._build_mode_specific_args(base_args)
            if final_args is None:
                return

            # Generate query
            query = generate_query_from_args(final_args)

            # Display result
            self._display_query(query)
            self.logger.info("Query issued")

        except ValueError as e:
            self._handle_error("Input Error", str(e), exit_on_error=False)
        except Exception as e:
            self._handle_error("Unexpected Error", str(e), exit_on_error=True)

    # =========================================================================
    # UI STATE MANAGEMENT METHODS
    # =========================================================================

    def _update_mode_visibility(self) -> None:
        """
        Update mode visibility
        """
        mode = self.current_mode
        config = self.MODE_CONFIGS.get(mode, self.MODE_CONFIGS["aql"])

        # Update labels
        self.platform_info_label.config(text=config["info"])
        self.input_label.config(text=config["label"])

        # Update hash type options based on mode
        self._update_hash_types_for_mode(mode)

        # Handle QID/EA widget visibility
        self._toggle_entry_widgets(
            show_qid=config["show_qid"],
            show_ea=config["show_ea"]
        )

        if mode == "defender":
            self.checkbox.grid(row=6, column=0, columnspan=2, sticky="nsew")
        else:
            self.checkbox.grid_remove()

    def _toggle_entry_widgets(self, show_qid: bool, show_ea: bool) -> None:
        """
        Toggle QID and EA entry widget visibility.

        Args:
        - show_qid (bool): Whether to show QID entry
        - show_ea (bool): Whether to show EA entry
        """

        # Handle QID entry
        if show_qid:
            self._show_entry_widget(
                widget_to_show=self.qid_entry,
                widget_to_hide=self.ea_entry,
                restore_var="saved_qid_input",
                save_var="saved_ea_input"
            )
        else:
            hide_entry_widget(self.qid_entry)

        # Handle EA entry
        if show_ea:
            self._show_entry_widget(
                widget_to_show=self.ea_entry,
                widget_to_hide=self.qid_entry,
                restore_var="saved_ea_input",
                save_var="saved_qid_input"
            )
        else:
            hide_entry_widget(self.ea_entry)

    def _show_entry_widget(self, widget_to_show, widget_to_hide, restore_var: str, save_var: str) -> None:
        """
        Show entry widget and manage state.

        Args:
        - widget_to_show: Widget to make visible
        - widget_to_hide: Widget to hide
        - restore_var (str): Attribute name for restoring saved input
        - save_var (str): Attribute name for saving current input
        """

        if not widget_to_show.winfo_ismapped():
            # Save current input from other widget
            setattr(self, save_var, widget_to_hide.get())

            # Restore and show target widget
            widget_to_show.delete(0, tk.END)
            widget_to_show.insert(0, getattr(self, restore_var))
            widget_to_show.grid(row=0, column=0, sticky=GRID_STICKY_EW)

        # Hide other widget if visible
        if widget_to_hide.winfo_ismapped():
            widget_to_hide.grid_remove()

    def _update_hash_type_visibility(self) -> None:
        """
        Update hash visibility
        """

        is_hash_type = self.current_type == "hash"

        # Check for valid hash type
        if is_hash_type:
            self.hash_type_combobox.grid()
            self.hash_type_label.grid()
        else:
            self.hash_type_combobox.grid_remove()
            self.hash_type_label.grid_remove()

    def _update_hash_types_for_mode(self, mode: str) -> None:
        """
        Update hash type combobox based on selected mode.

        Args:
        - mode (str): Current mode selection
        """

        # Get supported types
        supported_types = get_supported_hash_types(mode)
        self.hash_type_combobox['values'] = supported_types

        current_hash_type = self.current_hash_type

        if current_hash_type not in supported_types:
            self.hash_type_var.set(DEFAULT_HASH_TYPE)
        else:
            self.hash_type_var.set(current_hash_type)

    # =========================================================================
    # CLIPBOARD UTILITY METHODS
    # =========================================================================

    def copy_to_clipboard(self) -> None:
        """
        Copy to clipboard
        """

        text = self.output_text.get("1.0", tk.END).strip()

        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            show_info_message("Copied", "Query copied to clipboard.")
            self.logger.info("Query copied to clipboard")
