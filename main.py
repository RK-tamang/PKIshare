# PKIshare - Secure Digital Certificate File Sharing System
# main.py

import tkinter as tk
from gui.app import PKIshareApp

if __name__ == "__main__":
    root = tk.Tk()
    app = PKIshareApp(root)
    root.mainloop()

