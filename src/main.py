"""
A simple program that generates a search query based on a given list.

Author: Olof Magnusson
Date: 2025-07-02
"""

VERSION = "1.0.0"
AUTHOR = "olofmagn"

import sys
import questionary
import tkinter as tk

from colorama import Fore, Style

from .gui import QueryGeneratorGUI
from utils import create_parser
from utils import generate_query_from_args
from utils import get_logger

BANNER = rf"""

  ___            ___                       __  __
 |_ _|___   ___ / _ \ _   _  ___ _ __ _   _\ \/ /
  | |/ _ \ / __| | | | | | |/ _ \ '__| | | |\  /
  | | (_) | (__| |_| | |_| |  __/ |  | |_| |/  \
 |___\___/ \___|\__\_\\__,_|\___|_|   \__, /_/\_\
                                      |___/

Welcome to the application!
Enjoy using the app, and feel free to share any feature requests or feedback!
Version: {VERSION} {AUTHOR}
"""

def main():
    """
    Main driver
    """

    logger = get_logger()  
    
    if len(sys.argv) > 1:
        parser = create_parser()
        try:
            args = parser.parse_args()
            query = generate_query_from_args(args)
            print(query) 
            logger.info("CLI query generated successfully")
        except SystemExit:
            logger.error("CLI argument parsing failed")
            sys.exit(1)
        except Exception as e:
            logger.error(f"CLI query generation failed: {e}")
            print(f"Error: {e}")
            sys.exit(1)
        return

    print(BANNER)
    
    try:
        mode = questionary.select(
            "Choose interface mode:",
            choices=["GUI", "CLI", "EXIT"]
        ).ask()
        
        if mode in (None, "EXIT"):
            print("Goodbye!")
            sys.exit(1)
        
        if mode == "CLI":
            parser = create_parser()
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}Here's how to use the CLI:\n{Style.RESET_ALL}")
            parser.print_help()
        else:  # GUI
            root = tk.Tk()
            app = QueryGeneratorGUI(root)
            root.mainloop()     
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    
if __name__ == "__main__":    
    main()    

