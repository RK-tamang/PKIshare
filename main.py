"""PKIshare - Secure Digital Certificate and File Sharing System.

This module serves as the main entry point for the PKIshare application,
providing a secure platform for digital certificate and file sharing.
"""

import os
import sys
from tkinter import Tk

from gui.app import PKIshareApp

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    """Main entry point for PKIshare application."""
    root = Tk()
    PKIshareApp(root)

    # Center the window on screen
    window_width = 1100
    window_height = 750
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_cordinate = int((screen_width / 2) - (window_width / 2))
    y_cordinate = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x_cordinate}+{y_cordinate}")

    root.mainloop()


if __name__ == "__main__":
    main()
