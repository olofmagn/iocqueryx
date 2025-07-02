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

from utils.generate_queries import generate_query_from_args
from utils.utility import create_parser

class QueryGeneratorGUI:
    TIME_RANGES = ["5 MINUTES", "10 MINUTES", "30 MINUTES", "1 HOUR", "3 HOURS", "12 HOURS", "1 DAY"]
    def __init__(self, root):
        self.root = root
        self.root.title("IocQueryX - IOC Hunting Query Generator")
        self.root.minsize(500, 400)  # optional minimum size
        self.root.resizable(False, False)

        self.frame = ttk.Frame(root, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.create_widgets()
        self.setup_trace_callbacks()
        self.update_field_visibility()
        self.update_hash_type_visibility()

    def create_widgets(self) -> None:
        """
        Create all widgets
        """

        # === Input file ===
        ttk.Label(self.frame, text="Input File:").grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.input_entry = ttk.Entry(self.frame)
        self.input_entry.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
        ttk.Button(self.frame, text="Browse", command=self.browse_file).grid(row=0, column=2, sticky="ew", padx=2, pady=2)

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

        # === QIDS ===
        self.qid_label = ttk.Label(self.frame, text="QIDs (comma-separated):")
        self.qid_label.grid(row=4, column=0, sticky="nsew", padx=2, pady=2)
        self.qid_entry = ttk.Entry(self.frame)
        self.qid_entry.grid(row=4, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === Event Actions ===
        self.ea_label = ttk.Label(self.frame, text="Event Actions (comma-separated):")
        self.ea_label.grid(row=5, column=0, sticky="nsew", padx=2, pady=2)
        self.ea_entry = ttk.Entry(self.frame)
        self.ea_entry.grid(row=5, column=1, columnspan=2, sticky="nsew", padx=2, pady=2)

        # === Time range ===
        ttk.Label(self.frame, text="Time Range:").grid(row=6, column=0, sticky="w", padx=2)
        time_frame = ttk.Frame(self.frame)
        time_frame.grid(row=6, column=1, columnspan=2, sticky="w", padx=2, pady=2)
        self.lookback_var = tk.StringVar(value=self.TIME_RANGES[1])  # default "10 MINUTES"
        self.time_entry = ttk.Entry(time_frame, textvariable=self.lookback_var, width=15)
        self.time_entry.pack(side="left")

        self.btn_time_prev = ttk.Button(time_frame, text="❮", style="Arrow.TButton", padding=(6,0), width=2, command=lambda: self.change_time_range(-1))
        self.btn_time_prev.pack(side="left", padx=1)
        self.btn_time_next = ttk.Button(time_frame, text="❯", style="Arrow.TButton", padding=(6,0), width=2, command=lambda: self.change_time_range(1))
        self.btn_time_next.pack(side="right", padx=1)

        # === Generate query ===
        ttk.Button(self.frame, text="Generate Query", command=self.generate_query).grid(row=7, column=0, columnspan=3, pady=10, sticky="nsew", padx=2)

        # === Output text ===
        self.output_text = ScrolledText(self.frame, height=10, wrap=tk.WORD)
        self.output_text.grid(row=8, column=0, columnspan=3, sticky="nsew", pady=5, padx=2)
        
        # === Copy to Clipboard ===
        ttk.Button(self.frame, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=9, column=0, columnspan=3, pady=5, sticky="nsew", padx=2)
        
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
        self.copyright_label.grid(row=12, column=2, sticky="w", pady=(0, 10), padx=5)

    def setup_trace_callbacks(self) -> None:
        """
        Setup trace callbacks
        """

        self.mode_var.trace_add("write", lambda *args: self.update_field_visibility())
        self.type_var.trace_add("write", lambda *args: self.update_hash_type_visibility())

    def browse_file(self) -> None:
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

    def generate_query(self) -> None:
        """
        Generate query based on fetch elements from args
        """
        
        # Validate required fields
        if not self.input_entry.get():
            messagebox.showerror("Input missing", "Please select an input file")
            return 0
        
        if not self.mode_var.get():
            messagebox.showerror("Input missing", "Please enter a valid mode")
            return 0

        if not self.type_var.get():
            messagebox.showerror("Input missing", "Please enter a valid type")
            return 0
        
        # Build base args
        args = [
            "-i", self.input_entry.get(),
            "-m", self.mode_var.get(),
            "-t", self.type_var.get(),
            "-ht", self.hash_type_var.get(),
            "-l", self.lookback_var.get()
        ]

        # Validation of optional fields
        if self.qid_entry.get():
            qids = self.qid_entry.get().split(",")
            for qid in qids:
                if not qid.strip().isdigit():
                    messagebox.showerror("Invalid QID", f"QID '{qid}' must be an integer.")
                    return 0

            args.extend(["-q"] + [qid.strip() for qid in qids])

        if self.ea_entry.get():
            event_actions = self.ea_entry.get().split(",")
            for ea in event_actions:
                ea = ea.strip()
                if not ea:
                    messagebox.showerror("Invalid input","Event action can not be empty.")
                    return 0

            args.extend(["-ea"] + self.ea_entry.get().split(","))

        try:
            query = generate_query_from_args(args)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, query)
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))
            sys.exit(1)

    def copy_to_clipboard(self):
        """
        Copy text to clipboard
        """

        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo("Copied", "Query copied to clipboard.")

    def update_field_visibility(self):
        """
        Update field visibility based on the platform
        Using disabled field to show to user that there other options - works as this is an minimal application.
        """

        mode = self.mode_var.get()

        if mode == "aql":
            self.set_widget_state(self.qid_label, self.qid_entry, "normal")
            self.platform_info_label.config(text="Using AQL Search query mode")
        else:
            self.set_widget_state(self.qid_label, self.qid_entry, "disabled")

        if mode == "es":
            self.set_widget_state(self.ea_label, self.ea_entry, "normal")
            self.platform_info_label.config(text="Using Elastic Search query mode")
        else:
            self.set_widget_state(self.ea_label, self.ea_entry, "disabled")

        if mode == "defender":
            self.set_widget_state(self.ea_label, self.ea_entry, "normal")
            self.platform_info_label.config(text="Using Defender Search query mode")
            self.set_widget_state(self.ea_label, self.ea_entry, "disabled")
            self.set_widget_state(self.qid_label, self.qid_entry, "disabled")

    def set_widget_state(self, label: tk.Label, entry: tk.Entry, state: str, clear: bool=True) -> None:
        """
        Sets the widget state based on platform
        """

        label.configure(state=state)
        entry.configure(state=state)

        if clear and state == "normal":
            entry.delete(0, 'end')
            entry.insert(0, "")

    def update_hash_type_visibility(self):
        """
        Update hash type visibility
        """

        if self.type_var.get() in ("ip", "domain"):
            self.hash_type_combobox.configure(state="disabled")
            self.hash_type_label.configure(text="Hash Type:")
        else:
            self.hash_type_combobox.configure(state="normal")
            self.hash_type_label.configure(text="Hash Type:")

    def change_time_range(self, direction: int) -> None:
        """
        Change time range based on the direction.
        """

        current = self.lookback_var.get()

        if current in self.TIME_RANGES:
            idx = self.TIME_RANGES.index(current)
            new_idx = (idx + direction) % len(self.TIME_RANGES)
            self.lookback_var.set(self.TIME_RANGES[new_idx])
