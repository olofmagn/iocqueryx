"""
A simple program that generates a search query based on a given list to identify first point of contact for further investigation.

Author: Olof Magnusson
Date: 2025-07-02
"""

import tkinter as tk
import sys
import questionary

from colorama import init, Fore, Style
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from typing import Optional, List
from tkinter import StringVar

from utils.generate_queries import generate_query_from_args
from utils.configuration import get_logger
from utils.configuration import normalize_lookback

class QueryGeneratorGUI:
    def __init__(self, root) -> None:
        self.logger = get_logger()
        self.saved_qid_input = ""
        self.saved_ea_input = ""

        self.time_ranges = [
            ("5m", "5 MINUTES"),
            ("10m", "10 MINUTES"),
            ("30m", "30 MINUTES"),
            ("1h", "1 HOUR"),
            ("3h", "3 HOURS"),
            ("12h", "12 HOURS"),
            ("1d", "1 DAY")
        ]

        # Add this after your time_ranges setup:
        self.MODE_CONFIGS = {
            "aql": {
                "info": "Using AQL Search query mode",
                "label": "QID:",
                "show_qid": True,
                "show_ea": False
            },
            "es": {
                "info": "Using Elastic Search query mode", 
                "label": "EA:",
                "show_qid": False,
                "show_ea": True
            },
            "defender": {
                "info": "Using Defender Search query mode",
                "label": "",
                "show_qid": False,
                "show_ea": False
            }
        }

        self.display_values = [display for _, display in self.time_ranges]

        self.root = root
        self.root.title("IocQueryX - IOC Hunting Query Generator")
        self.root.minsize(500, 400)  # optional minimum size
        self.root.resizable(False, False)

        self.frame = ttk.Frame(root, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)

        self._create_widgets()
        self._setup_trace_callbacks()
        self._update_mode_visibility()
        self._update_hash_type_visibility()

    def _validate_inputs(self) -> bool:
        """
        Centralized input validation
        """

        if not self.input_entry_var.get():
            self._show_validation_error("Please select an input file.")
            return False
        return True

    def _build_base_args(self) -> List[str]:
        """
        Build the base arguments list for query generation
        """

        return [
            "-i", self.input_entry_var.get(),
            "-m", self.current_mode,
            "-t", self.current_type,
            "-ht", self.current_hash_type,
            "-l", self.current_lookback
        ]

    def _validate_time_range(self) -> bool:
        """Validate the selected time range"""
        duration = normalize_lookback(self.current_lookback, self.current_mode)
        if duration is None:
            self._show_validation_error("Invalid time range")
            return False
        return True

    def _build_mode_specific_args(self, base_args: List[str]) -> Optional[List[str]]:
        """
        Add mode-specific arguments to the base args
        """

        args = base_args.copy()
        
        if self.current_mode == "aql":
            qids = self._validate_comma_separated_input(self.qid_entry.get(), "QID", is_numeric=True)
            if qids is None:
                return None
            if qids:
                args.extend(["-q"] + qids)
        
        elif self.current_mode == "es":
            eas = self._validate_comma_separated_input(self.ea_entry.get(), "EA")
            if eas is None:
                return None
            if eas:
                args.extend(["-ea"] + eas)
        
        return args

    def _display_query(self, query: str) -> None:
        """
        Display the generated query in the output text widget
        """

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, query)

    def _handle_error(self, title: str, message: str, exit_on_error: bool = False) -> None:
        """
        Centralized error handling with consistent behavior
        """

        messagebox.showerror(title, message)
        self.logger.error(f"{title}: {message}")
        if exit_on_error:
            sys.exit(1)

    
    @property
    def current_mode(self) -> str:
        """
        Cache current mode to avoid repeated StringVar.get() calls
        """

        return self.mode_var.get().lower()

    @property 
    def current_type(self) -> str:
        """
        Cache current type to avoid repeated StringVar.get() calls
        """

        return self.type_var.get()

    @property
    def current_hash_type(self) -> str:
        """
        Cache current hash type to avoid repeated StringVar.get() calls
        """

        return self.hash_type_var.get()

    @property
    def current_lookback(self) -> str:
        """
        Cache current lookback value to avoid repeated StringVar.get() calls
        """

        return self.lookback_var.get()

    def _create_widgets(self) -> None:
        """
        Create all widgets
        """

        # === Input file ===
        ttk.Label(self.frame, text="Input File:").grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.input_entry_var = ttk.Entry(self.frame)
        self.input_entry_var.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
        ttk.Button(self.frame, text="Browse", command=self._browse_file).grid(row=0, column=2, sticky="ew", padx=2, pady=2)

        # === Mode selection ===
        ttk.Label(self.frame, text="Mode:").grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        self.mode_var = tk.StringVar(value="aql")
        self.mode_combobox = ttk.Combobox(self.frame,
                                          textvariable=self.mode_var, 
                                          values=["aql", "es", "defender"],
                                          state="readonly")
        self.mode_combobox.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === Type selection ===
        ttk.Label(self.frame, text="Type:").grid(row=2, column=0, sticky="nsew", padx=2, pady=2)
        self.type_var = tk.StringVar(value="ip")
        self.type_combobox = ttk.Combobox(self.frame, 
                                          textvariable=self.type_var, 
                                          values=["ip", "domain", "hash"],
                                          state="readonly")
        self.type_combobox.grid(row=2, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === Hash type ===
        self.hash_type_label = ttk.Label(self.frame, text="Hash Type:")
        self.hash_type_label.grid(row=3, column=0, sticky="nsew", padx=2, pady=2)
        self.hash_type_var = tk.StringVar(value="sha256")
        self.hash_type_combobox = ttk.Combobox(self.frame, 
                                               textvariable=self.hash_type_var, 
                                               values=["md5", "sha1", "sha256"],
                                               state="readonly")
        self.hash_type_combobox.grid(row=3, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === QID/EA ===
        self.input_label = ttk.Label(self.frame, text="QID:")
        self.input_label.grid(row=4, column=0, sticky="w", padx=2, pady=2)
        self.qid_entry = ttk.Entry(self.frame)
        self.qid_entry.grid(row=4, column=1, columnspan=2, sticky="ew", padx=2, pady=2)

        self.ea_entry = ttk.Entry(self.frame)
        self.ea_entry.grid(row=4, column=1, columnspan=2, sticky="ew", padx=2, pady=2)
        self.ea_entry.grid_remove()  # Hide by default

        # === Time range ===
        ttk.Label(self.frame, text="Time Range:").grid(row=6, column=0, sticky="w", padx=2)
        time_frame = ttk.Frame(self.frame)
        time_frame.grid(row=6, column=1, columnspan=2, sticky="w", padx=2, pady=2)
        self.lookback_var = tk.StringVar(value=self.display_values[1])  # default "10 MINUTES"
        self.time_entry = ttk.Entry(time_frame, textvariable=self.lookback_var, width=15)
        self.time_entry.pack(side="left")
        
        self.btn_time_prev = ttk.Button(time_frame, text="❮", style="Arrow.TButton", padding=(6,0), width=2, command=lambda: self._change_time_range(-1))
        self.btn_time_prev.pack(side="left", padx=1)
        self.btn_time_next = ttk.Button(time_frame, text="❯", style="Arrow.TButton", padding=(6,0), width=2, command=lambda: self._change_time_range(1))
        self.btn_time_next.pack(side="right", padx=1)

        # === Generate query ===
        ttk.Button(self.frame, text="Generate Query", command=self._generate_query).grid(row=7, column=0, columnspan=3, pady=10, sticky="nsew", padx=2)

        # === Output text ===
        self.output_text = ScrolledText(self.frame, height=10, wrap=tk.WORD)
        self.output_text.grid(row=8, column=0, columnspan=3, sticky="nsew", pady=5, padx=2)
        
        # === Copy to Clipboard ===
        ttk.Button(self.frame, text="Copy to Clipboard", command=self._copy_to_clipboard).grid(row=9, column=0, columnspan=3, pady=5, sticky="nsew", padx=2)
        
        # === Separator ===
        separator = ttk.Separator(self.frame, orient='horizontal')
        separator.grid(row=10, column=0, columnspan=3, sticky='nsew', pady=(10, 5))

        # === Platform info label ===
        self.platform_info_label = ttk.Label(self.frame, text="")
        self.platform_info_label.grid(row=11, column=0, columnspan=3, sticky="nsew", pady=(0, 2), padx=5)
        self.platform_info_label.config(anchor="center", justify="center")

        # === Copyright label ===
        self.copyright_label = ttk.Label(
        self.frame, text="© 2025 olofmagn", font=("Segoe UI", 8, "italic"), foreground="gray50"
        )
        self.copyright_label.grid(row=13, column=2, sticky="e", pady=(0, 10), padx=5)

    def _setup_trace_callbacks(self) -> None:
        """
        Setup trace callbacks
        """

        self.mode_var.trace_add("write", lambda *args: self._update_mode_visibility())
        self.type_var.trace_add("write", lambda *args: self._update_hash_type_visibility())

    def _browse_file(self) -> None:
        """
        Browser and insert files
        """

        try:
            file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
            if file_path:
                self.input_entry_var.delete(0, tk.END)
                self.input_entry_var.insert(0, file_path)
        except Exception as e:
            messagebox.showerror(f"Error", "Failed to load file: {e}")
            sys.exit(1)

    def _generate_query(self) -> None:
        """
        Generate query using a clean, step-by-step approach with proper error handling
        """

        try:
            #Validate inputs
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
                return  # Error already shown by _build_mode_specific_args
            
            # Generate query
            query = generate_query_from_args(final_args)
            
            # Display result
            self._display_query(query)
            
        except ValueError as e:
            self._handle_error("Input Error", str(e), exit_on_error=False)
        except Exception as e:
            self._handle_error("Unexpected Error", str(e), exit_on_error=True)

    def _validate_comma_separated_input(self, raw_input: str, label: str, is_numeric: bool = False) -> Optional[List[str]]:
        """
        Validate comma-separated input with single-pass processing
        """

        if not raw_input.strip():
            return []
        
        items = [item.strip() for item in raw_input.split(",") if item.strip()]
        
        if not items:
            self._show_validation_error(f"{label} contains no valid entries.")
            return None
        
        # Validate numeric values in single pass if needed
        if is_numeric:
            invalid_items = [item for item in items if not item.isdigit()]
            if invalid_items:
                # Show ALL invalid items at once, not just the first one
                invalid_list = "', '".join(invalid_items)
                self._show_validation_error(f"{label} contains invalid integers: '{invalid_list}'")
                return None
        
        return items
    
    def _show_validation_error(self, message: str) -> None:
        """
        Helper method to centralize validation error handling
        """
        
        messagebox.showerror("Invalid input", message)
        self.logger.error(message)

    def _copy_to_clipboard(self) -> None:
        """
        Copy text to clipboard
        """

        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo("Copied", "Query copied to clipboard.")
            self.logger.info("Query copied to clipboard")

    def _update_mode_visibility(self) -> None:
        mode = self.current_mode
        config = self.MODE_CONFIGS.get(mode, self.MODE_CONFIGS["aql"])
        
        # Update labels
        self.platform_info_label.config(text=config["info"])
        self.input_label.config(text=config["label"])
        
        # Handle QID entry widget
        if config["show_qid"]:
            if not self.qid_entry.winfo_viewable():  # Only show if hidden
                self.saved_ea_input = self.ea_entry.get()
                self.qid_entry.delete(0, tk.END)
                self.qid_entry.insert(0, self.saved_qid_input)
                self.qid_entry.grid()
            if self.ea_entry.winfo_viewable():  # Hide EA if visible
                self.ea_entry.grid_remove()
        else:
            if self.qid_entry.winfo_viewable():  # Only hide if visible
                self.qid_entry.grid_remove()
        
        # Handle EA entry widget  
        if config["show_ea"]:
            if not self.ea_entry.winfo_viewable():  # Only show if hidden
                self.saved_qid_input = self.qid_entry.get()
                self.ea_entry.delete(0, tk.END)
                self.ea_entry.insert(0, self.saved_ea_input)
                self.ea_entry.grid()
            if self.qid_entry.winfo_viewable():  # Hide QID if visible
                self.qid_entry.grid_remove()
        else:
            if self.ea_entry.winfo_viewable():  # Only hide if visible
                self.ea_entry.grid_remove()

    def _update_hash_type_visibility(self) -> None:
        """
        Show or hide the hash type selector depending on the selected type.
        """

        is_hash_type = self.current_type == "hash"
        self.hash_type_label.config(text="Hash Type:")

        if is_hash_type:
            self.hash_type_combobox.grid() 
            self.hash_type_label.grid()     
        else:
            self.hash_type_combobox.grid_remove()
            self.hash_type_label.grid_remove()

    def _change_time_range(self, direction: int) -> None:
        current_display = self.lookback_var.get()

        try:
            current_idx = self.display_values.index(current_display)
        except ValueError:
            current_idx = 1

        # Update display label in entry
        new_idx = (current_idx + direction) % len(self.display_values)
        self.lookback_var.set(self.display_values[new_idx])


