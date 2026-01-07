# PKIshare - Secure Digital Certificate and File Sharing System
# gui/app.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import base64

from core.secure_share import PKIshareCore


class PKIshareApp:
    """Main GUI application for PKI-based secure file sharing."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("PKIshare - Secure Digital Certificate File Sharing")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)

        self.core = PKIshareCore()
        self.session_key = None
        self.share_key = None
        self.share_unlocked = False

        self.setup_styles()

        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.render_auth_page()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('Title.TLabel', font=('Arial', 20, 'bold'), foreground='#2c3e50')
        style.configure('Heading.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Accent.TButton', font=('Arial', 11, 'bold'))

    def clear_screen(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    def render_auth_page(self):
        self.clear_screen()

        ttk.Label(self.main_container, text="PKIshare", style='Title.TLabel').pack(pady=(0, 10))
        ttk.Label(
            self.main_container,
            text="Secure Digital Certificate File Sharing System"
        ).pack(pady=(0, 30))

        self.auth_notebook = ttk.Notebook(self.main_container)
        self.auth_notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        self.login_tab = ttk.Frame(self.auth_notebook)
        self.auth_notebook.add(self.login_tab, text="   Login   ")
        self.create_login_panel(self.login_tab)

        self.register_tab = ttk.Frame(self.auth_notebook)
        self.auth_notebook.add(self.register_tab, text="   Register   ")
        self.create_register_panel(self.register_tab)

        self.auth_notebook.select(self.login_tab)

    def create_login_panel(self, parent):
        login_frame = ttk.LabelFrame(parent, text=" Login ", padding=20)
        login_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.username_input = ttk.Entry(login_frame, width=40, font=('Arial', 11))
        self.username_input.grid(row=0, column=1, pady=10, padx=(10, 0))

        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.password_input = ttk.Entry(login_frame, width=40, show="*", font=('Arial', 11))
        self.password_input.grid(row=1, column=1, pady=10, padx=(10, 0))

        ttk.Button(login_frame, text="Login", command=self.execute_login).grid(row=2, column=0, columnspan=2, pady=20)

    def create_register_panel(self, parent):
        reg_frame = ttk.LabelFrame(parent, text=" Register New User ", padding=20)
        reg_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(reg_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.reg_username = ttk.Entry(reg_frame, width=40, font=('Arial', 11))
        self.reg_username.grid(row=0, column=1, pady=10, padx=(10, 0))

        ttk.Label(reg_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.reg_password = ttk.Entry(reg_frame, width=40, show="*", font=('Arial', 11))
        self.reg_password.grid(row=1, column=1, pady=10, padx=(10, 0))

        ttk.Label(reg_frame, text="Confirm Password:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.reg_confirm = ttk.Entry(reg_frame, width=40, show="*", font=('Arial', 11))
        self.reg_confirm.grid(row=2, column=1, pady=10, padx=(10, 0))

        ttk.Button(reg_frame, text="Register", command=self.handle_registration).grid(row=3, column=0, columnspan=2, pady=20)

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
        else:
            messagebox.showerror("Error", "Username already exists")

    def display_dashboard(self):
        self.clear_screen()

        header = ttk.Frame(self.main_container)
        header.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(header, text=f"Welcome, {self.core.current_username}!", style='Title.TLabel').pack(side=tk.LEFT)
        ttk.Button(header, text="Logout", command=self.terminate_session).pack(side=tk.RIGHT)

        notebook = ttk.Notebook(self.main_container)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        self.setup_share_panel(notebook)
        self.setup_files_panel(notebook)
        self.setup_users_panel(notebook)
        self.setup_share_panel_main(notebook)
        self.setup_cert_panel(notebook)

    def setup_share_panel(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Share File")

        file_frame = ttk.LabelFrame(tab, text="Select File to Share", padding=15)
        file_frame.pack(fill=tk.X, padx=20, pady=15)
        self.target_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.target_path_var, width=70).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        ttk.Button(file_frame, text="Browse...", command=self.select_file_dialog).pack(side=tk.RIGHT)

        recip_frame = ttk.LabelFrame(tab, text="Select Recipients", padding=15)
        recip_frame.pack(fill=tk.X, padx=20, pady=15)

        all_users = self.core.get_all_users()
        others = [u for u in all_users if u != self.core.current_username]
        self.recipient_states = {}

        if others:
            for i, user in enumerate(others):
                var = tk.BooleanVar()
                chk = ttk.Checkbutton(recip_frame, text=user, variable=var)
                chk.grid(row=i // 4, column=i % 4, sticky=tk.W, padx=15, pady=5)
                self.recipient_states[user] = var
        else:
            ttk.Label(recip_frame, text="No other registered users", foreground="gray").pack(pady=10)

        ttk.Button(tab, text="Encrypt & Share File", command=self.initiate_file_share).pack(pady=25)

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
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="My Files")

        top_frame = ttk.Frame(tab)
        top_frame.pack(fill=tk.X, padx=20, pady=10)
        ttk.Button(top_frame, text="Refresh", command=self.update_files_view).pack(side=tk.RIGHT)

        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        columns = ("ID", "Filename", "Owner", "Recipients", "Date")
        self.files_view = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for col, width in zip(columns, [120, 250, 120, 250, 130]):
            self.files_view.heading(col, text=col)
            self.files_view.column(col, width=width, anchor=tk.W if col != "Date" else tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.files_view.yview)
        self.files_view.configure(yscrollcommand=scrollbar.set)
        self.files_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        action_frame = ttk.Frame(tab)
        action_frame.pack(fill=tk.X, padx=20, pady=15)
        ttk.Button(action_frame, text="Download Selected", command=self.process_file_download).pack(side=tk.LEFT, padx=10)
        ttk.Button(action_frame, text="Revoke Access", command=self.revoke_file_access).pack(side=tk.LEFT, padx=10)

        self.update_files_view()

    def update_files_view(self):
        for item in self.files_view.get_children():
            self.files_view.delete(item)

        files = self.core.fetch_shared_collection()
        for ef in files:
            recipients = []
            # Get file keys to determine recipients
            file_keys = self.core.db.get_file_keys(ef["id"])
            for k in file_keys:
                if k["user_id"] != ef["owner_id"]:
                    recipients.append(k.get("username", ""))
            
            recip_str = "(Only me)" if not recipients else ", ".join(recipients[:4])
            if len(recipients) > 4:
                recip_str += "..."

            self.files_view.insert("", tk.END, iid=ef["file_id"], values=(
                ef["file_id"][:15] + "...",
                ef["filename"],
                ef.get("owner_name", "Unknown"),
                recip_str,
                ef["timestamp"][:10]
            ))

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

        ttk.Label(dialog, text=f"Manage access to '{file_data['filename']}:", font=('Arial', 12, 'bold')).pack(pady=15)

        current_frame = ttk.LabelFrame(dialog, text=" Current Access ", padding=10)
        current_frame.pack(fill=tk.X, padx=20, pady=10)

        revoke_vars = {}
        file_keys = self.core.db.get_file_keys(file_data["id"])
        for k in file_keys:
            if k["user_id"] != self.core.current_user_id:
                var = tk.BooleanVar()
                ttk.Checkbutton(current_frame, text=f"{k.get('username', 'Unknown')} (has access)", variable=var).pack(anchor=tk.W, padx=10, pady=2)
                revoke_vars[k["user_id"]] = var

        if not revoke_vars:
            ttk.Label(current_frame, text="No other users have access", foreground='gray').pack(anchor=tk.W, padx=10)

        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)

        def perform_revoke():
            revoked = []
            for user_id, var in revoke_vars.items():
                if var.get():
                    # Get username
                    user = self.core.db.get_user_by_id(user_id)
                    if user and self.core.remove_file_access(file_id, user["username"]):
                        revoked.append(user["username"])
            messagebox.showinfo("Success", f"Access revoked for: {', '.join(revoked) if revoked else 'none'}")
            dialog.destroy()
            self.update_files_view()

        ttk.Button(button_frame, text="Revoke Selected", command=perform_revoke).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=10)

    def setup_users_panel(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Users")

        frame = ttk.LabelFrame(tab, text="Registered Users", padding=20)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

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
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Shared Repository")

        has_share_password = self.core.check_share_protection(self.core.current_username)

        if not has_share_password:
            self._render_set_share_password(tab)
        elif not self.share_unlocked:
            self._render_share_password_prompt(tab)
        else:
            self._build_share_interface(tab)

    def _render_set_share_password(self, parent):
        prompt_frame = ttk.Frame(parent)
        prompt_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

        ttk.Label(prompt_frame, text="Set Share Password", font=('Arial', 18, 'bold'), foreground='#3498db').pack(pady=(0, 10))
        ttk.Label(prompt_frame, text="Set a password to protect your shared files", font=('Arial', 11), foreground='#7f8c8d').pack(pady=(0, 20))

        ttk.Label(prompt_frame, text="Share Password:").pack(pady=(10, 5))
        share_pwd_entry = ttk.Entry(prompt_frame, width=30, show="*", font=('Arial', 11))
        share_pwd_entry.pack(pady=5)

        ttk.Label(prompt_frame, text="Confirm Password:").pack(pady=(5, 5))
        share_confirm_entry = ttk.Entry(prompt_frame, width=30, show="*", font=('Arial', 11))
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

        ttk.Button(prompt_frame, text="Set Password", command=save_password).pack(pady=20)

    def _render_share_password_prompt(self, parent):
        prompt_frame = ttk.Frame(parent)
        prompt_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

        ttk.Label(prompt_frame, text="Shared Repository Locked", font=('Arial', 18, 'bold'), foreground='#e74c3c').pack(pady=(0, 10))
        ttk.Label(prompt_frame, text="Enter your share password", font=('Arial', 11), foreground='#7f8c8d').pack(pady=(0, 20))

        ttk.Label(prompt_frame, text="Share Password:").pack(pady=(10, 5))
        share_pwd_entry = ttk.Entry(prompt_frame, width=30, show="*", font=('Arial', 11))
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

        ttk.Button(prompt_frame, text="Unlock", command=verify_password).pack(pady=20)

    def _build_share_interface(self, parent):
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, padx=20, pady=20)
        ttk.Button(top_frame, text="Change Password", command=self.modify_share_password).pack(side=tk.RIGHT, padx=5)

        add_frame = ttk.LabelFrame(parent, text=" Add to Repository ", padding=15)
        add_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        self.share_file_path_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.share_file_path_var, width=60).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        ttk.Button(add_frame, text="Browse...", command=self.select_share_file).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(add_frame, text="Encrypt & Store", command=self.store_in_share).pack(side=tk.LEFT)

        list_frame = ttk.LabelFrame(parent, text=" My Shared Files ", padding=15)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        top_list_frame = ttk.Frame(list_frame)
        top_list_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(top_list_frame, text="Refresh", command=self.refresh_share_view).pack(side=tk.RIGHT)

        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Filename", "Size", "Date", "ID")
        self.share_view = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for col, width in zip(columns, [250, 100, 130, 150]):
            self.share_view.heading(col, text=col)
            self.share_view.column(col, width=width, anchor=tk.W if col != "Size" and col != "Date" else tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.share_view.yview)
        self.share_view.configure(yscrollcommand=scrollbar.set)
        self.share_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        action_frame = ttk.Frame(list_frame)
        action_frame.pack(fill=tk.X, pady=15)
        ttk.Button(action_frame, text="Download Selected", command=self.download_share_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(action_frame, text="Delete Selected", command=self.remove_share_file).pack(side=tk.LEFT, padx=10)

        self.share_info_label = ttk.Label(list_frame, text="", font=('Arial', 10), foreground='#7f8c8d')
        self.share_info_label.pack(pady=(10, 0))

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
            self.share_view.insert("", tk.END, iid=sf["share_id"], values=(
                sf["filename"],
                size_str,
                sf["timestamp"][:10],
                sf["share_id"][:20] + "..."
            ))

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

        ttk.Label(dialog, text="Change Share Password", font=('Arial', 14, 'bold'), foreground='#3498db').pack(pady=20)

        ttk.Label(dialog, text="Current Password:").pack(pady=5)
        current_pwd = ttk.Entry(dialog, width=30, show="*", font=('Arial', 11))
        current_pwd.pack(pady=5)

        ttk.Label(dialog, text="New Password:").pack(pady=5)
        new_pwd = ttk.Entry(dialog, width=30, show="*", font=('Arial', 11))
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
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Your Certificate")

        cert = self.core.get_certificate()

        if cert:
            info = (
                f"Certificate (PKIshare)\n"
                f"Subject: {cert['subject']}\n"
                f"Serial: {cert['serial']}\n"
                f"Issuer: {cert['issuer']}\n"
                f"Valid From: {cert['valid_from'][:10]}\n"
                f"Valid To: {cert['valid_to'][:10]}\n"
                f"Status: VALID\n"
            )
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


# Ensure newline at end of file

