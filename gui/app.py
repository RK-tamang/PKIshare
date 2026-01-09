# PKIshare - Secure Digital Certificate and File Sharing System
# gui/app.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import base64

from core.secure_share import PKIshareCore


class PKIshareApp:
    """Main GUI application for PKI-based secure file sharing."""
    
    # Modern color palette
    COLORS = {
        'bg_primary': '#f8f9fa',
        'bg_secondary': '#ffffff',
        'accent': '#0984e3',
        'accent_hover': '#0773c7',
        'success': '#00b894',
        'error': '#d63031',
        'text_primary': '#2d3436',
        'text_secondary': '#636e72',
        'text_light': '#b2bec3',
        'border': '#dfe6e9',
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("PKIshare - Secure Digital Certificate File Sharing")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        self.root.configure(bg=self.COLORS['bg_primary'])

        self.core = PKIshareCore()
        self.session_key = None
        self.share_key = None
        self.share_unlocked = False

        self.setup_styles()

        self.main_container = tk.Frame(self.root, bg=self.COLORS['bg_primary'])
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.render_auth_page()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', 
            font=('Segoe UI', 24, 'bold'), 
            foreground=self.COLORS['accent'],
            background=self.COLORS['bg_primary'])
        
        style.configure('Subtitle.TLabel', 
            font=('Segoe UI', 12), 
            foreground=self.COLORS['text_secondary'],
            background=self.COLORS['bg_primary'])
        
        style.configure('Heading.TLabel', 
            font=('Segoe UI', 14, 'bold'), 
            foreground=self.COLORS['text_primary'],
            background=self.COLORS['bg_secondary'])
        
        style.configure('Card.TLabel',
            font=('Segoe UI', 10),
            foreground=self.COLORS['text_secondary'],
            background=self.COLORS['bg_secondary'])
        
        style.configure('Modern.TNotebook.Tab',
            font=('Segoe UI', 10, 'bold'),
            padding=[15, 8])
        
        style.configure('Treeview',
            font=('Segoe UI', 10),
            rowheight=32)
        
        style.configure('Treeview.Heading',
            font=('Segoe UI', 10, 'bold'),
            background=self.COLORS['border'])

    def create_modern_button(self, parent, text, command, bg=None, fg='white', hover_color=None):
        """Create a modern styled button"""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=('Segoe UI', 10, 'bold'),
            bg=bg if bg else self.COLORS['accent'],
            fg=fg,
            activebackground=hover_color if hover_color else self.COLORS['accent_hover'],
            activeforeground='white',
            relief='flat',
            bd=0,
            cursor='hand2',
            padx=20,
            pady=8,
        )
        return btn

    def create_card(self, parent, **kwargs):
        """Create a card-style container"""
        card = tk.Frame(
            parent,
            bg=self.COLORS['bg_secondary'],
            highlightbackground=self.COLORS['border'],
            highlightthickness=1,
            **kwargs
        )
        return card

    def clear_screen(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    def render_auth_page(self):
        self.clear_screen()

        # Header
        header_frame = tk.Frame(self.main_container, bg=self.COLORS['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(20, 10))
        
        icon_label = tk.Label(
            header_frame,
            text="",
            font=('Segoe UI', 32),
            bg=self.COLORS['bg_primary'],
            fg=self.COLORS['accent']
        )
        icon_label.pack(pady=(0, 10))
        
        ttk.Label(self.main_container, text="PKIshare", style='Title.TLabel').pack()
        ttk.Label(
            self.main_container,
            text="Secure Digital Certificate File Sharing System",
            style='Subtitle.TLabel'
        ).pack(pady=(0, 30))

        auth_card = self.create_card(self.main_container)
        auth_card.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        self.auth_notebook = ttk.Notebook(auth_card)
        self.auth_notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        self.login_tab = tk.Frame(self.auth_notebook, bg=self.COLORS['bg_secondary'])
        self.auth_notebook.add(self.login_tab, text="  Login  ")
        self.create_login_panel(self.login_tab)

        self.register_tab = tk.Frame(self.auth_notebook, bg=self.COLORS['bg_secondary'])
        self.auth_notebook.add(self.register_tab, text="  Register  ")
        self.create_register_panel(self.register_tab)

        self.auth_notebook.select(self.login_tab)

    def create_login_panel(self, parent):
        login_frame = self.create_card(parent)
        login_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        ttk.Label(login_frame, text="Welcome Back", style='Heading.TLabel').pack(anchor=tk.W, pady=(0, 20))
        ttk.Label(login_frame, text="Username", style='Card.TLabel').pack(anchor=tk.W)
        self.username_input = ttk.Entry(login_frame, width=45)
        self.username_input.pack(fill=tk.X, pady=(5, 15))

        ttk.Label(login_frame, text="Password", style='Card.TLabel').pack(anchor=tk.W)
        self.password_input = ttk.Entry(login_frame, width=45, show="*")
        self.password_input.pack(fill=tk.X, pady=(5, 20))

        self.create_modern_button(
            login_frame, "Login", self.execute_login,
            bg=self.COLORS['accent'], hover_color=self.COLORS['accent_hover']
        ).pack(fill=tk.X, pady=(10, 0))

    def create_register_panel(self, parent):
        reg_frame = self.create_card(parent)
        reg_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        ttk.Label(reg_frame, text="Create Account", style='Heading.TLabel').pack(anchor=tk.W, pady=(0, 20))
        ttk.Label(reg_frame, text="Username", style='Card.TLabel').pack(anchor=tk.W)
        self.reg_username = ttk.Entry(reg_frame, width=45)
        self.reg_username.pack(fill=tk.X, pady=(5, 15))

        ttk.Label(reg_frame, text="Password", style='Card.TLabel').pack(anchor=tk.W)
        self.reg_password = ttk.Entry(reg_frame, width=45, show="*")
        self.reg_password.pack(fill=tk.X, pady=(5, 15))

        ttk.Label(reg_frame, text="Confirm Password", style='Card.TLabel').pack(anchor=tk.W)
        self.reg_confirm = ttk.Entry(reg_frame, width=45, show="*")
        self.reg_confirm.pack(fill=tk.X, pady=(5, 20))

        self.create_modern_button(
            reg_frame, "Create Account", self.handle_registration,
            bg=self.COLORS['accent'], hover_color=self.COLORS['accent_hover']
        ).pack(fill=tk.X, pady=(10, 0))

    def execute_login(self):
        username = self.username_input.get().strip()
        password = self.password_input.get()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        if self.core.authenticate_user(username, password):
            self.session_key = password
            self.share_key = None
            self.share_unlocked = False
            self.display_dashboard()
            self.update_files_view()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def handle_registration(self):
        username = self.reg_username.get().strip()
        pwd1 = self.reg_password.get()
        pwd2 = self.reg_confirm.get()
        if not username or not pwd1:
            messagebox.showerror("Error", "All fields are required")
            return
        if pwd1 != pwd2:
            messagebox.showerror("Error", "Passwords do not match")
            return
        if len(pwd1) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        if self.core.create_user_account(username, pwd1):
            messagebox.showinfo("Success", f"User '{username}' registered successfully!")
            self.reg_username.delete(0, tk.END)
            self.reg_password.delete(0, tk.END)
            self.reg_confirm.delete(0, tk.END)
            self.auth_notebook.select(self.login_tab)
            self.username_input.focus_set()
        else:
            messagebox.showerror("Error", "Username already exists")

    def display_dashboard(self):
        self.clear_screen()

        header = tk.Frame(self.main_container, bg=self.COLORS['bg_primary'])
        header.pack(fill=tk.X, pady=(0, 20))

        welcome_frame = tk.Frame(header, bg=self.COLORS['bg_primary'])
        welcome_frame.pack(side=tk.LEFT)
        ttk.Label(welcome_frame, text=f"Welcome, {self.core.current_username}!", style='Title.TLabel').pack(anchor=tk.W)

        btn_frame = tk.Frame(header, bg=self.COLORS['bg_primary'])
        btn_frame.pack(side=tk.RIGHT)
        self.create_modern_button(btn_frame, "Logout", self.terminate_session, bg=self.COLORS['error'], hover_color='#c0392b').pack()

        notebook = ttk.Notebook(self.main_container)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        self.setup_share_panel(notebook)
        self.setup_files_panel(notebook)
        self.setup_users_panel(notebook)
        self.setup_share_panel_main(notebook)
        self.setup_cert_panel(notebook)

    def setup_share_panel(self, notebook):
        tab = tk.Frame(notebook, bg=self.COLORS['bg_secondary'])
        notebook.add(tab, text="  Share File  ")

        main_card = self.create_card(tab)
        main_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        file_frame = self.create_card(main_card)
        file_frame.pack(fill=tk.X, padx=15, pady=15)
        ttk.Label(file_frame, text="Select File to Share", style='Card.TLabel').pack(anchor=tk.W, pady=(0, 10))

        file_input_frame = tk.Frame(file_frame, bg=self.COLORS['bg_secondary'])
        file_input_frame.pack(fill=tk.X)
        self.target_path_var = tk.StringVar()
        ttk.Entry(file_input_frame, textvariable=self.target_path_var, width=70).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        self.create_modern_button(file_input_frame, "Browse", self.select_file_dialog, bg=self.COLORS['text_secondary']).pack(side=tk.RIGHT)

        recip_frame = self.create_card(main_card)
        recip_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        ttk.Label(recip_frame, text="Select Recipients", style='Card.TLabel').pack(anchor=tk.W, pady=(0, 10))

        all_users = self.core.get_all_users()
        others = [u for u in all_users if u != self.core.current_username]
        self.recipient_states = {}

        if others:
            recip_grid = tk.Frame(recip_frame, bg=self.COLORS['bg_secondary'])
            recip_grid.pack(fill=tk.X)
            for i, user in enumerate(others):
                var = tk.BooleanVar()
                chk = tk.Checkbutton(recip_grid, text=user, variable=var, font=('Segoe UI', 10),
                    bg=self.COLORS['bg_secondary'], fg=self.COLORS['text_primary'],
                    activebackground=self.COLORS['bg_secondary'], selectcolor=self.COLORS['bg_secondary'])
                chk.grid(row=i // 3, column=i % 3, sticky=tk.W, padx=10, pady=5)
                self.recipient_states[user] = var
        else:
            ttk.Label(recip_frame, text="No other registered users", style='Card.TLabel', foreground=self.COLORS['text_light']).pack(pady=10)

        self.create_modern_button(main_card, "Encrypt & Share File", self.initiate_file_share, bg=self.COLORS['accent']).pack(pady=(0, 15))

    def select_file_dialog(self):
        filepath = filedialog.askopenfilename(title="Choose a file to share")
        if filepath:
            self.target_path_var.set(filepath)

    def initiate_file_share(self):
        filepath = self.target_path_var.get()
        if not filepath or not Path(filepath).exists():
            messagebox.showerror("Error", "Please select a valid file")
            return
        recipients = [user for user, var in self.recipient_states.items() if var.get()]
        if not recipients:
            messagebox.showerror("Error", "Please select at least one recipient")
            return
        if self.core.distribute_file(filepath, recipients, self.session_key):
            messagebox.showinfo("Success", f"File shared with: {', '.join(recipients)}")
            self.target_path_var.set("")
            for var in self.recipient_states.values():
                var.set(False)
            self.update_files_view()
        else:
            messagebox.showerror("Error", "Failed to share file")

    def setup_files_panel(self, notebook):
        tab = tk.Frame(notebook, bg=self.COLORS['bg_secondary'])
        notebook.add(tab, text="  My Files  ")

        main_card = self.create_card(tab)
        main_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        top_bar = tk.Frame(main_card, bg=self.COLORS['bg_secondary'])
        top_bar.pack(fill=tk.X, padx=15, pady=15)
        ttk.Label(top_bar, text="Shared Files", style='Heading.TLabel').pack(side=tk.LEFT)
        self.create_modern_button(top_bar, "Refresh", self.update_files_view, bg=self.COLORS['border'], fg=self.COLORS['text_primary']).pack(side=tk.RIGHT)

        # Split view: file list and preview
        content_frame = tk.Frame(main_card, bg=self.COLORS['bg_secondary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=15)

        # Left side: file list
        left_frame = tk.Frame(content_frame, bg=self.COLORS['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 7))

        tree_frame = tk.Frame(left_frame, bg=self.COLORS['bg_secondary'])
        tree_frame.pack(fill=tk.BOTH, expand=True)
        columns = ("ID", "Filename", "Owner", "Recipients", "Date")
        self.files_view = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for col, width in zip(columns, [120, 250, 120, 250, 130]):
            self.files_view.heading(col, text=col)
            self.files_view.column(col, width=width, anchor=tk.W if col != "Date" else tk.CENTER)
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.files_view.yview)
        self.files_view.configure(yscrollcommand=scrollbar.set)
        self.files_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event for preview
        self.files_view.bind("<<TreeviewSelect>>", self.on_file_selected)

        # Right side: preview panel
        self.preview_card = self.create_card(content_frame)
        self.preview_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(7, 0))
        
        self.preview_label = ttk.Label(self.preview_card, text="Select a file to preview", 
                                       font=('Segoe UI', 12), foreground=self.COLORS['text_light'],
                                       background=self.COLORS['bg_secondary'])
        self.preview_label.pack(pady=50)
        
        self.preview_image_label = tk.Label(self.preview_card, bg=self.COLORS['bg_secondary'])
        self.preview_image_label.pack_forget()
        
        self.preview_text = tk.Text(self.preview_card, wrap=tk.WORD, font=('Consolas', 10),
                                    bg='#f5f5f5', relief='flat', state='disabled')
        self.preview_text.pack_forget()

        action_frame = tk.Frame(main_card, bg=self.COLORS['bg_secondary'])
        action_frame.pack(fill=tk.X, padx=15, pady=15)
        self.create_modern_button(action_frame, "Download", self.process_file_download, bg=self.COLORS['success']).pack(side=tk.LEFT, padx=(0, 10))
        self.create_modern_button(action_frame, "Revoke Access", self.revoke_file_access, bg=self.COLORS['error']).pack(side=tk.LEFT, padx=(0, 10))
        self.create_modern_button(action_frame, "Grant Access", self.grant_file_access_dialog, bg=self.COLORS['accent']).pack(side=tk.LEFT)

        self.update_files_view()

    def on_file_selected(self, event):
        """Handle file selection for preview."""
        selection = self.files_view.selection()
        if not selection:
            self.clear_preview()
            return
        
        file_id = selection[0]
        self.show_file_preview(file_id)

    def clear_preview(self):
        """Clear the preview panel."""
        self.preview_label.pack_forget()
        self.preview_image_label.pack_forget()
        self.preview_text.pack_forget()
        self.preview_label.configure(text="Select a file to preview")
        self.preview_label.pack(pady=50)

    def show_file_preview(self, file_id):
        """Show a preview of the selected file."""
        file_data = self.core.db.get_file_by_id(file_id)
        if not file_data:
            self.clear_preview()
            return
        
        filename = file_data["filename"]
        ext = Path(filename).suffix.lower()
        
        # Create a temporary file to decrypt
        import tempfile
        import os
        
        temp_path = tempfile.mktemp(suffix=filename)
        try:
            if self.core.retrieve_file(file_id, temp_path, self.session_key):
                # Show preview based on file type
                if ext in ['.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.md', '.log', '.csv']:
                    self.show_text_preview(temp_path)
                elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico']:
                    self.show_image_preview(temp_path)
                else:
                    self.preview_label.configure(text=f"Preview not available for\n{filename}\n\nClick Download to save the file")
                    self.preview_label.pack(pady=50)
                    self.preview_image_label.pack_forget()
                    self.preview_text.pack_forget()
            else:
                self.preview_label.configure(text="Unable to preview file")
                self.preview_label.pack(pady=50)
        except Exception as e:
            self.preview_label.configure(text=f"Preview error:\n{str(e)}")
            self.preview_label.pack(pady=50)
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def show_text_preview(self, filepath):
        """Show text file preview."""
        self.preview_label.pack_forget()
        self.preview_image_label.pack_forget()
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(5000)  # Limit to 5000 chars
            self.preview_text.config(state='normal')
            self.preview_text.delete('1.0', tk.END)
            self.preview_text.insert('1.0', content)
            if len(content) >= 5000:
                self.preview_text.insert(tk.END, '\n\n... (content truncated for preview)')
            self.preview_text.config(state='disabled')
        except Exception as e:
            self.preview_text.config(state='normal')
            self.preview_text.delete('1.0', tk.END)
            self.preview_text.insert('1.0', f"Error reading file: {e}")
            self.preview_text.config(state='disabled')

    def show_image_preview(self, filepath):
        """Show image file preview."""
        try:
            from PIL import Image, ImageTk
            
            self.preview_text.pack_forget()
            self.preview_label.pack_forget()
            self.preview_image_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            image = Image.open(filepath)
            
            # Resize image to fit in preview area (max 400x300)
            image.thumbnail((400, 300))
            photo = ImageTk.PhotoImage(image)
            
            self.preview_image_label.configure(image=photo)
            self.preview_image_label.image = photo  # Keep reference
        except ImportError:
            self.preview_image_label.pack_forget()
            self.preview_label.configure(text="Image preview requires\nPIL library.\n\nClick Download to save.")
            self.preview_label.pack(pady=50)
        except Exception as e:
            self.preview_image_label.pack_forget()
            self.preview_label.configure(text=f"Error loading image:\n{str(e)}")
            self.preview_label.pack(pady=50)

    def update_files_view(self):
        for item in self.files_view.get_children():
            self.files_view.delete(item)
        files = self.core.fetch_shared_collection()
        for ef in files:
            recipients = []
            file_keys = self.core.db.get_file_keys(ef["id"])
            for k in file_keys:
                if k["user_id"] != ef["owner_id"]:
                    recipients.append(k.get("username", ""))
            recip_str = "(Only me)" if not recipients else ", ".join(recipients[:4])
            if len(recipients) > 4:
                recip_str += "..."
            self.files_view.insert("", tk.END, iid=ef["file_id"], values=(
                ef["file_id"][:15] + "...", ef["filename"], ef.get("owner_name", "Unknown"), recip_str, ef["timestamp"][:10]))

    def process_file_download(self):
        selection = self.files_view.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file to download")
            return
        file_id = selection[0]
        file_data = self.core.db.get_file_by_id(file_id)
        if not file_data:
            messagebox.showerror("Error", "File not found")
            return
        save_path = filedialog.asksaveasfilename(title="Save decrypted file as", initialfile=file_data["filename"])
        if not save_path:
            return
        if self.core.retrieve_file(file_id, save_path, self.session_key):
            messagebox.showinfo("Success", "File downloaded and decrypted successfully!")
        else:
            messagebox.showerror("Error", "Download failed")

    def revoke_file_access(self):
        selection = self.files_view.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file")
            return
        file_id = selection[0]
        file_data = self.core.db.get_file_by_id(file_id)
        if not file_data:
            messagebox.showerror("Error", "File not found")
            return
        if file_data["owner_id"] != self.core.current_user_id:
            messagebox.showerror("Error", "Only the file owner can revoke access")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Manage Access")
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.COLORS['bg_primary'])

        ttk.Label(dialog, text=f"Manage access to '{file_data['filename']}'", style='Heading.TLabel').pack(pady=20)
        current_frame = self.create_card(dialog)
        current_frame.pack(fill=tk.X, padx=20, pady=10)
        ttk.Label(current_frame, text="Current Access", style='Card.TLabel').pack(anchor=tk.W, pady=(0, 10))

        revoke_vars = {}
        file_keys = self.core.db.get_file_keys(file_data["id"])
        for k in file_keys:
            if k["user_id"] != self.core.current_user_id:
                var = tk.BooleanVar()
                chk = tk.Checkbutton(current_frame, text=f"{k.get('username', 'Unknown')} (has access)", variable=var,
                    font=('Segoe UI', 10), bg=self.COLORS['bg_secondary'], fg=self.COLORS['text_primary'],
                    activebackground=self.COLORS['bg_secondary'], selectcolor=self.COLORS['bg_secondary'])
                chk.pack(anchor=tk.W, padx=10, pady=2)
                revoke_vars[k["user_id"]] = var

        if not revoke_vars:
            ttk.Label(current_frame, text="No other users have access", style='Card.TLabel', foreground=self.COLORS['text_light']).pack(anchor=tk.W, padx=10)

        button_frame = tk.Frame(dialog, bg=self.COLORS['bg_primary'])
        button_frame.pack(pady=20)

        def perform_revoke():
            revoked = []
            for user_id, var in revoke_vars.items():
                if var.get():
                    user = self.core.db.get_user_by_id(user_id)
                    if user and self.core.remove_file_access(file_id, user["username"]):
                        revoked.append(user["username"])
            messagebox.showinfo("Success", f"Access revoked for: {', '.join(revoked) if revoked else 'none'}")
            dialog.destroy()
            self.update_files_view()

        self.create_modern_button(button_frame, "Revoke Selected", perform_revoke, bg=self.COLORS['error']).pack(side=tk.LEFT, padx=10)
        self.create_modern_button(button_frame, "Close", dialog.destroy, bg=self.COLORS['border'], fg=self.COLORS['text_primary']).pack(side=tk.LEFT, padx=10)

    def grant_file_access_dialog(self):
        """Open dialog to grant access to a previously revoked user."""
        selection = self.files_view.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file")
            return
        file_id = selection[0]
        file_data = self.core.db.get_file_by_id(file_id)
        if not file_data:
            messagebox.showerror("Error", "File not found")
            return
        if file_data["owner_id"] != self.core.current_user_id:
            messagebox.showerror("Error", "Only the file owner can grant access")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Grant Access")
        dialog.geometry("450x400")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.COLORS['bg_primary'])

        ttk.Label(dialog, text=f"Grant access to '{file_data['filename']}'", style='Heading.TLabel').pack(pady=20)

        # Get list of users who don't have access
        all_users = self.core.get_all_users()
        file_keys = self.core.db.get_file_keys(file_data["id"])
        users_with_access = [k["user_id"] for k in file_keys]
        users_without_access = [u for u in all_users if self.core.get_user_id_by_username(u) not in users_with_access and u != self.core.current_username]

        if not users_without_access:
            ttk.Label(dialog, text="All users already have access", style='Card.TLabel', foreground=self.COLORS['text_light']).pack(pady=20)
            button_frame = tk.Frame(dialog, bg=self.COLORS['bg_primary'])
            button_frame.pack(pady=20)
            self.create_modern_button(button_frame, "Close", dialog.destroy, bg=self.COLORS['border'], fg=self.COLORS['text_primary']).pack()
            return

        grant_frame = self.create_card(dialog)
        grant_frame.pack(fill=tk.X, padx=20, pady=10)
        ttk.Label(grant_frame, text="Grant Access To", style='Card.TLabel').pack(anchor=tk.W, pady=(0, 10))

        grant_vars = {}
        grant_grid = tk.Frame(grant_frame, bg=self.COLORS['bg_secondary'])
        grant_grid.pack(fill=tk.X)

        for i, user in enumerate(users_without_access):
            var = tk.BooleanVar()
            chk = tk.Checkbutton(grant_grid, text=user, variable=var, font=('Segoe UI', 10),
                bg=self.COLORS['bg_secondary'], fg=self.COLORS['text_primary'],
                activebackground=self.COLORS['bg_secondary'], selectcolor=self.COLORS['bg_secondary'])
            chk.grid(row=i // 2, column=i % 2, sticky=tk.W, padx=10, pady=5)
            grant_vars[user] = var

        button_frame = tk.Frame(dialog, bg=self.COLORS['bg_primary'])
        button_frame.pack(pady=20)

        def perform_grant():
            granted = []
            for username, var in grant_vars.items():
                if var.get():
                    if self.core.grant_file_access(file_id, username, self.session_key):
                        granted.append(username)
            messagebox.showinfo("Success", f"Access granted to: {', '.join(granted) if granted else 'none'}")
            dialog.destroy()
            self.update_files_view()

        self.create_modern_button(button_frame, "Grant Selected", perform_grant, bg=self.COLORS['success']).pack(side=tk.LEFT, padx=10)
        self.create_modern_button(button_frame, "Close", dialog.destroy, bg=self.COLORS['border'], fg=self.COLORS['text_primary']).pack(side=tk.LEFT, padx=10)

    def setup_users_panel(self, notebook):
        tab = tk.Frame(notebook, bg=self.COLORS['bg_secondary'])
        notebook.add(tab, text="  Users  ")

        main_card = self.create_card(tab)
        main_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        ttk.Label(main_card, text="Registered Users", style='Heading.TLabel').pack(anchor=tk.W, padx=15, pady=15)

        frame = tk.Frame(main_card, bg=self.COLORS['bg_secondary'])
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        columns = ("Status", "Username")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        tree.heading("Status", text="")
        tree.heading("Username", text="Username")
        tree.column("Status", width=60, anchor=tk.CENTER)
        tree.column("Username", width=200, anchor=tk.W)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        for user in sorted(self.core.get_all_users()):
            status = "You" if user == self.core.current_username else ""
            tree.insert("", tk.END, values=(status, user))

    def setup_share_panel_main(self, notebook):
        tab = tk.Frame(notebook, bg=self.COLORS['bg_secondary'])
        notebook.add(tab, text="  Shared Repository  ")
        has_share_password = self.core.check_share_protection(self.core.current_username)
        if not has_share_password:
            self._render_set_share_password(tab)
        elif not self.share_unlocked:
            self._render_share_password_prompt(tab)
        else:
            self._build_share_interface(tab)

    def _render_set_share_password(self, parent):
        prompt_frame = tk.Frame(parent, bg=self.COLORS['bg_secondary'])
        prompt_frame.pack(fill=tk.BOTH, expand=True)
        card = self.create_card(prompt_frame)
        card.pack(expand=True, padx=100, pady=80)
        ttk.Label(card, text="Set Share Password", style='Heading.TLabel').pack(pady=(0, 10))
        ttk.Label(card, text="Set a password to protect your shared files", style='Card.TLabel').pack(pady=(0, 20))
        ttk.Label(card, text="Share Password:", style='Card.TLabel').pack()
        share_pwd_entry = ttk.Entry(card, width=30, show="*", font=('Segoe UI', 11))
        share_pwd_entry.pack(pady=5)
        ttk.Label(card, text="Confirm Password:", style='Card.TLabel').pack()
        share_confirm_entry = ttk.Entry(card, width=30, show="*", font=('Segoe UI', 11))
        share_confirm_entry.pack(pady=5)

        def save_password():
            pwd = share_pwd_entry.get()
            conf = share_confirm_entry.get()
            if not pwd or pwd != conf or len(pwd) < 4:
                messagebox.showerror("Error", "Invalid password")
                return
            if self.core.configure_share_password(pwd):
                self.share_key = pwd
                self.share_unlocked = True
                messagebox.showinfo("Success", "Share password set!")
                for widget in parent.winfo_children():
                    widget.destroy()
                self._build_share_interface(parent)

        self.create_modern_button(card, "Set Password", save_password, bg=self.COLORS['accent']).pack(pady=25)

    def _render_share_password_prompt(self, parent):
        prompt_frame = tk.Frame(parent, bg=self.COLORS['bg_secondary'])
        prompt_frame.pack(fill=tk.BOTH, expand=True)
        card = self.create_card(prompt_frame)
        card.pack(expand=True, padx=100, pady=80)
        ttk.Label(card, text="Shared Repository Locked", style='Heading.TLabel').pack(pady=(0, 10))
        ttk.Label(card, text="Enter your share password", style='Card.TLabel').pack(pady=(0, 20))
        ttk.Label(card, text="Share Password:", style='Card.TLabel').pack()
        share_pwd_entry = ttk.Entry(card, width=30, show="*", font=('Segoe UI', 11))
        share_pwd_entry.pack(pady=5)

        def verify_password():
            if self.core.validate_share_credentials(self.core.current_username, share_pwd_entry.get()):
                self.share_key = share_pwd_entry.get()
                self.share_unlocked = True
                for widget in parent.winfo_children():
                    widget.destroy()
                self._build_share_interface(parent)
            else:
                messagebox.showerror("Error", "Incorrect share password")

        self.create_modern_button(card, "Unlock", verify_password, bg=self.COLORS['success']).pack(pady=25)

    def _build_share_interface(self, parent):
        main_card = self.create_card(parent)
        main_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        top_bar = tk.Frame(main_card, bg=self.COLORS['bg_secondary'])
        top_bar.pack(fill=tk.X, padx=15, pady=15)
        ttk.Label(top_bar, text="Shared Repository", style='Heading.TLabel').pack(side=tk.LEFT)
        self.create_modern_button(top_bar, "Change Password", self.modify_share_password, bg=self.COLORS['border'], fg=self.COLORS['text_primary']).pack(side=tk.RIGHT, padx=5)

        add_frame = self.create_card(main_card)
        add_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        ttk.Label(add_frame, text="Add to Repository", style='Card.TLabel').pack(anchor=tk.W, pady=(0, 10))
        input_row = tk.Frame(add_frame, bg=self.COLORS['bg_secondary'])
        input_row.pack(fill=tk.X)
        self.share_file_path_var = tk.StringVar()
        ttk.Entry(input_row, textvariable=self.share_file_path_var, width=60).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        self.create_modern_button(input_row, "Browse", self.select_share_file, bg=self.COLORS['text_secondary']).pack(side=tk.LEFT, padx=(0, 10))
        self.create_modern_button(input_row, "Encrypt & Store", self.store_in_share, bg=self.COLORS['success']).pack(side=tk.LEFT)

        list_card = self.create_card(main_card)
        list_card.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        top_list = tk.Frame(list_card, bg=self.COLORS['bg_secondary'])
        top_list.pack(fill=tk.X, padx=15, pady=15)
        ttk.Label(top_list, text="My Shared Files", style='Card.TLabel').pack(side=tk.LEFT)
        self.create_modern_button(top_list, "Refresh", self.refresh_share_view, bg=self.COLORS['border'], fg=self.COLORS['text_primary']).pack(side=tk.RIGHT)

        tree_frame = tk.Frame(list_card, bg=self.COLORS['bg_secondary'])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15)
        columns = ("Filename", "Size", "Date", "ID")
        self.share_view = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for col, width in zip(columns, [250, 100, 130, 150]):
            self.share_view.heading(col, text=col)
            self.share_view.column(col, width=width, anchor=tk.W if col != "Size" and col != "Date" else tk.CENTER)
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.share_view.yview)
        self.share_view.configure(yscrollcommand=scrollbar.set)
        self.share_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        action_frame = tk.Frame(list_card, bg=self.COLORS['bg_secondary'])
        action_frame.pack(fill=tk.X, padx=15, pady=15)
        self.create_modern_button(action_frame, "Download", self.download_share_file, bg=self.COLORS['success']).pack(side=tk.LEFT, padx=(0, 10))
        self.create_modern_button(action_frame, "Delete", self.remove_share_file, bg=self.COLORS['error']).pack(side=tk.LEFT)

        self.share_info_label = ttk.Label(list_card, text="", font=('Segoe UI', 10), foreground=self.COLORS['text_secondary'], background=self.COLORS['bg_secondary'])
        self.share_info_label.pack(pady=(0, 15))
        self.refresh_share_view()

    def select_share_file(self):
        filepath = filedialog.askopenfilename(title="Choose a file to encrypt and store")
        if filepath:
            self.share_file_path_var.set(filepath)

    def store_in_share(self):
        filepath = self.share_file_path_var.get()
        if not filepath or not Path(filepath).exists():
            messagebox.showerror("Error", "Please select a valid file")
            return
        if self.core.store_in_share(filepath, self.session_key):
            messagebox.showinfo("Success", "File stored in repository!")
            self.share_file_path_var.set("")
            self.refresh_share_view()
        else:
            messagebox.showerror("Error", "Failed to add file")

    def refresh_share_view(self):
        for item in self.share_view.get_children():
            self.share_view.delete(item)
        files = self.core.list_share_contents()
        total_size = 0
        for sf in files:
            size_str = self._format_size(sf.get("size", 0))
            total_size += sf.get("size", 0)
            self.share_view.insert("", tk.END, iid=sf["share_id"], values=(sf["filename"], size_str, sf["timestamp"][:10], sf["share_id"][:20] + "..."))
        self.share_info_label.config(text=f"Total files: {len(files)} | Total size: {self._format_size(total_size)}")

    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def download_share_file(self):
        selection = self.share_view.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file")
            return
        share_id = selection[0]
        sf = self.core.db.get_shared_file_by_id(share_id)
        if not sf:
            messagebox.showerror("Error", "File not found")
            return
        save_path = filedialog.asksaveasfilename(title="Save decrypted file as", initialfile=sf["filename"])
        if not save_path:
            return
        if self.core.extract_from_share(share_id, save_path, self.session_key):
            messagebox.showinfo("Success", "File downloaded successfully!")
        else:
            messagebox.showerror("Error", "Download failed")

    def remove_share_file(self):
        selection = self.share_view.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file")
            return
        share_id = selection[0]
        sf = self.core.db.get_shared_file_by_id(share_id)
        if not sf:
            messagebox.showerror("Error", "File not found")
            return
        if messagebox.askyesno("Confirm", f"Delete '{sf['filename']}'?"):
            if self.core.remove_from_share(share_id):
                messagebox.showinfo("Success", "File deleted")
                self.refresh_share_view()

    def modify_share_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Share Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text="Change Share Password", font=('Segoe UI', 14, 'bold'), foreground=self.COLORS['accent']).pack(pady=20)
        ttk.Label(dialog, text="Current Password:").pack(pady=5)
        current_pwd = ttk.Entry(dialog, width=30, show="*")
        current_pwd.pack(pady=5)
        ttk.Label(dialog, text="New Password:").pack(pady=5)
        new_pwd = ttk.Entry(dialog, width=30, show="*")
        new_pwd.pack(pady=5)

        def save_new_password():
            if self.core.validate_share_credentials(self.core.current_username, current_pwd.get()):
                if self.core.configure_share_password(new_pwd.get()):
                    messagebox.showinfo("Success", "Password changed!")
                    dialog.destroy()
            else:
                messagebox.showerror("Error", "Current password incorrect")

        ttk.Button(dialog, text="Save New Password", command=save_new_password).pack(pady=20)

    def setup_cert_panel(self, notebook):
        tab = tk.Frame(notebook, bg=self.COLORS['bg_secondary'])
        notebook.add(tab, text="  Your Certificate  ")
        cert = self.core.get_certificate()
        if cert:
            info = (f"Certificate (PKIshare)\n" f"Subject: {cert['subject']}\n" f"Serial: {cert['serial']}\n"
                f"Issuer: {cert['issuer']}\n" f"Valid From: {cert['valid_from'][:10]}\n" f"Valid To: {cert['valid_to'][:10]}\n" f"Status: VALID\n")
        else:
            info = "No certificate found"
        label = ttk.Label(tab, text=info, font=('Courier', 10), background="#f0f0f0", relief="groove", padding=30)
        label.pack(padx=40, pady=40, fill=tk.X)

    def terminate_session(self):
        self.core.current_user_id = None
        self.core.current_username = None
        self.session_key = None
        self.share_key = None
        self.share_unlocked = False
        self.render_auth_page()

