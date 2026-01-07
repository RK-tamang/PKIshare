# PKIshare - Secure Digital Certificate and File Sharing System
# main.py

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import PKIshareApp
from tkinter import Tk


def main():
    """Main entry point for PKIshare application."""
    root = Tk()
    app = PKIshareApp(root)
    
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

