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
from utils.utility import get_logger
from utils.utility import normalize_lookback

class QueryGeneratorGUI:
    def __init__(self, root) -> None:
        self.logger = get_logger()
        self.saved_qid_input = ""
        self.saved_ea_input = ""

        self.INTERNAL_TIME_RANGES = ["5m", "10m", "30m", "1h", "3h", "12h", "1d"]
        self.DISPLAY_TIME_RANGES = ["5 MINUTES", "10 MINUTES", "30 MINUTES", "1 HOUR", "3 HOURS", "12 HOURS", "1 DAY"]

        self.internal_to_display = dict(zip(self.INTERNAL_TIME_RANGES, self.DISPLAY_TIME_RANGES))
        self.display_to_internal = dict(zip(self.DISPLAY_TIME_RANGES, self.INTERNAL_TIME_RANGES))

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

    def _create_widgets(self) -> None:
        """
        Create all widgets
        """

        # === Input file ===
        ttk.Label(self.frame, text="Input File:").grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.input_entry = ttk.Entry(self.frame)
        self.input_entry.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
        ttk.Button(self.frame, text="Browse", command=self._browse_file).grid(row=0, column=2, sticky="ew", padx=2, pady=2)

        # === Mode selection ===
        ttk.Label(self.frame, text="Mode:").grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        self.mode_var = tk.StringVar(value="aql")
        self.mode_combobox = ttk.Combobox(self.frame, textvariable=self.mode_var, values=["aql", "es", "defender"])
        self.mode_combobox.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === Type selection ===
        ttk.Label(self.frame, text="Type:").grid(row=2, column=0, sticky="nsew", padx=2, pady=2)
        self.type_var = tk.StringVar(value="ip")
        self.type_combobox = ttk.Combobox(self.frame, textvariable=self.type_var, values=["ip", "domain", "hash"])
        self.type_combobox.grid(row=2, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === Hash type ===
        self.hash_type_label = ttk.Label(self.frame, text="Hash Type:")
        self.hash_type_label.grid(row=3, column=0, sticky="nsew", padx=2, pady=2)
        self.hash_type_var = tk.StringVar(value="sha256")
        self.hash_type_combobox = ttk.Combobox(self.frame, textvariable=self.hash_type_var, values=["md5", "sha1", "sha256"])
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
        self.lookback_var = tk.StringVar(value=self.DISPLAY_TIME_RANGES[1])  # default "10 MINUTES"
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
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, file_path)
        except Exception as e:
            messagebox.showerror(f"Error", "Failed to load file: {e}")
            sys.exit(1)

    def _generate_query(self) -> None:
        """
        Generate query based on fetch elements from args
        """

        args = []
        
        # Validate required fields
        if not self.input_entry.get():
            messagebox.showerror("Input missing", "Please select an input file")
            self.logger.error("Input missing. Please select an input file")
            return 0
        
        if not self.mode_var.get():
            messagebox.showerror("Input missing", "Please enter a valid mode")
            self.logger.error("Input missing. Please enter a valid mode")
            return 0

        if not self.type_var.get():
            messagebox.showerror("Input missing", "Please enter a valid type")
            self.logger.error("Input missing. Please enter a valid type")
            return 0
        
        # Build base args
        args = [
            "-i", self.input_entry.get(),
            "-m", self.mode_var.get(),
            "-t", self.type_var.get(),
            "-ht", self.hash_type_var.get(),
            "-l", self.lookback_var.get()
        ]


        lookback = self.lookback_var.get()
        duration = normalize_lookback(lookback, self.mode_var.get())

        if duration is None:
            messagebox.showerror("Error", "Invalid time range")
            return 0

        if self.mode_var.get() == "aql":
            qids = self._validate_comma_separated_input(self.qid_entry.get(), "QID", is_numeric=True)

            if qids is None:
                return 0

            if qids:  # Only extend if non-empty
                args.extend(["-q"] + qids)
        
        elif self.mode_var.get() == "es":
            eas = self._validate_comma_separated_input(self.ea_entry.get(), "EA")

            if eas is None:
                return 0

            if eas: # Only extend if non-empty
                args.extend(["-ea"] + eas)

        try:
            query = generate_query_from_args(args)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, query)
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))
            sys.exit(1)

    def _validate_comma_separated_input(self, raw_input: str, label: str, is_numeric: bool = False) -> Optional[List[str]]:
        stripped_input = raw_input.strip()

        if not stripped_input:
            return []  

        items = [item.strip() for item in stripped_input.split(",")]

        for item in items:
            if not item:
                messagebox.showerror("Invalid input", f"{label} contains an empty entry.")
                self.logger.error(f"{label} contains an empty entry.")
                return None

            if is_numeric and not item.isdigit():
                messagebox.showerror("Invalid input", f"{label} '{item}' must be an valid integer.")
                self.logger.error(f"Invalid {label} - '{item}' must be an integer.")
                return None

        return items

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
        mode = self.mode_var.get().lower()

        # Update label/info if needed
        visibility_map = {
            "aql": {
                "info": "Using AQL Search query mode"
            },
            "es": {
                "info": "Using Elastic Search query mode"
            },
            "defender": {
                "info": "Using Defender Search query mode"
            }
        }

        if mode in visibility_map:
            self.platform_info_label.config(text=visibility_map[mode]["info"])

        # Handle toggle menu + entries visibility with defender

        if mode == "aql":
            self.saved_ea_input = self.ea_entry.get()

            self.input_label.config(text="QID:")
            self.qid_entry.grid()
            self.qid_entry.delete(0, tk.END)
            self.qid_entry.insert(0, self.saved_qid_input)

            self.ea_entry.grid_remove()

        elif mode == "es":
            self.saved_qid_input = self.qid_entry.get()

            self.input_label.config(text="EA:")
            self.ea_entry.grid()
            self.ea_entry.delete(0, tk.END)
            self.ea_entry.insert(0, self.saved_ea_input)

            self.qid_entry.grid_remove()

        else:
            self.qid_entry.grid_remove()
            self.ea_entry.grid_remove()
            self.input_label.config(text="")

    def _update_hash_type_visibility(self) -> None:

        """
        Show or hide the hash type selector depending on the selected type.
        """
        is_hash_type = self.type_var.get() not in ("ip", "domain")
        self.hash_type_label.config(text="Hash Type:")

        if is_hash_type:
            self.hash_type_combobox.grid() 
            self.hash_type_label.grid()     
        else:
            self.hash_type_combobox.grid_remove()  
            self.hash_type_label.grid_remove()   

    def _change_time_range(self, direction: int) -> None:
        current = self.lookback_var.get().strip().upper()

        if current in self.display_to_internal:
            internal = self.display_to_internal[current]
        else:
            internal = current.lower()

            if internal in self.internal_to_display:
                pass
            else:
                internal = self.INTERNAL_TIME_RANGES[0]

        # Find index in internal list for cycling
        idx = self.INTERNAL_TIME_RANGES.index(internal)
        new_idx = (idx + direction) % len(self.INTERNAL_TIME_RANGES)

        # Update display label in entry
        new_display = self.internal_to_display[self.INTERNAL_TIME_RANGES[new_idx]]
        self.lookback_var.set(new_display)

