import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
from datetime import datetime
import keyring
import configparser
import os
from ttkthemes import ThemedTk

# Configuration
PRODUCTION = False
ROOT_DOMAIN = "localhost:5000"
if PRODUCTION:
    ROOT_URI = f"https://{ROOT_DOMAIN}"
else:
    ROOT_URI = f"http://{ROOT_DOMAIN}"

class CredentialManager:
    def __init__(self):
        self.app_name = "NotesApp"
        self.config_file = "notes_app.ini"
        self.config = configparser.ConfigParser()
        
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.config['DEFAULT'] = {'last_username': ''}
            self.save_config()

    def save_config(self):
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)

    def save_credentials(self, username, password):
        try:
            keyring.set_password(self.app_name, username, password)
            self.config['DEFAULT']['last_username'] = username
            self.save_config()
            return True
        except Exception as e:
            print(f"Error saving credentials: {e}")
            return False

    def get_credentials(self):
        try:
            username = self.config['DEFAULT']['last_username']
            if username:
                password = keyring.get_password(self.app_name, username)
                return username, password
            return None, None
        except Exception as e:
            print(f"Error getting credentials: {e}")
            return None, None

    def clear_credentials(self):
        try:
            username = self.config['DEFAULT']['last_username']
            if username:
                keyring.delete_password(self.app_name, username)
            self.config['DEFAULT']['last_username'] = ''
            self.save_config()
            return True
        except Exception as e:
            print(f"Error clearing credentials: {e}")
            return False

class LoginWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Login to Notes App")
        self.credential_manager = CredentialManager()
        
        # Center the window
        window_width = 400
        window_height = 300
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        self.setup_ui()
        
        # Make window modal
        self.window.transient(parent)
        self.window.grab_set()
        
        # Try auto-login
        saved_username, saved_password = self.credential_manager.get_credentials()
        if saved_username and saved_password:
            self.username_var.set(saved_username)
            self.password_var.set(saved_password)
            self.remember_var.set(True)
            self.login()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill="both", expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Notes App", font=("Helvetica", 24))
        title_label.pack(pady=20)

        # Username
        ttk.Label(main_frame, text="Username:").pack(anchor="w")
        self.username_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.username_var).pack(fill="x", pady=(0, 10))

        # Password
        ttk.Label(main_frame, text="Password:").pack(anchor="w")
        self.password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.password_var, show="•").pack(fill="x", pady=(0, 10))

        # Remember me
        self.remember_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Remember me", variable=self.remember_var).pack(pady=10)

        # Login button
        ttk.Button(main_frame, text="Login", command=self.login).pack(fill="x", pady=10)

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        try:
            response = requests.post(f"{ROOT_URI}/api/external/get-notes", 
                                  json={
                                      "username": username,
                                      "password": password
                                  })
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and not data.get('success', True):
                    messagebox.showerror("Error", data.get('reason', 'Login failed'))
                    return
                
                if self.remember_var.get():
                    self.credential_manager.save_credentials(username, password)
                
                self.parent.on_login_success(username, password)
                self.window.destroy()
            else:
                messagebox.showerror("Error", "Login failed")
                
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Failed to connect to server: {str(e)}")

class NotesApp(ThemedTk):
    def __init__(self):
        super().__init__(theme="arc")
        
        self.title("Notes App")
        self.username = None
        self.password = None
        
        # Configure styles
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=30, font=("Helvetica", 10))
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        
        # Center the window, make it fullscreen
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        self.geometry(f"{screen_width}x{screen_height}+0+0")

        
        # Initialize main UI
        self.setup_main_ui()
        
        # Show login window
        LoginWindow(self)

    def show_login(self):
        self.login_window = LoginWindow(self)

    def setup_main_ui(self):
        # Menu bar
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)
        
        # File menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        
        # Main container
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill="both", expand=True)

    def setup_notes_list(self):
        # Clear main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Header frame
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(header_frame, text=f"Welcome, {self.username}", 
                 font=("Helvetica", 16)).pack(side="left")
        
        # Buttons
        buttons_frame = ttk.Frame(header_frame)
        buttons_frame.pack(side="right")
        
        ttk.Button(buttons_frame, text="New Note", 
                  command=self.show_add_note_dialog).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Refresh", 
                  command=self.refresh_notes).pack(side="left", padx=5)
        
        # Notes list
        notes_frame = ttk.Frame(self.main_frame)
        notes_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Create Treeview
        self.tree = ttk.Treeview(notes_frame, 
                                columns=("ID", "Title", "Last Changed"),
                                show="headings")
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("Title", text="Title")
        self.tree.heading("Last Changed", text="Last Changed")
        
        self.tree.column("ID", width=50)
        self.tree.column("Title", width=400)
        self.tree.column("Last Changed", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(notes_frame, orient="vertical", 
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind double-click
        self.tree.bind("<Double-1>", self.on_double_click)
        
        # Load notes
        self.refresh_notes()

    def on_login_success(self, username, password):
        self.username = username
        self.password = password
        self.setup_notes_list()
        self.deiconify()

    def logout(self):
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
            CredentialManager().clear_credentials()
            self.username = None
            self.password = None
            self.withdraw()
            self.login_window = LoginWindow(self)
            self.quit()

    def on_double_click(self, event):
        selected_items = self.tree.selection()
        if selected_items:
            self.show_edit_note_dialog()

    def refresh_notes(self):
        try:
            response = requests.post(f"{ROOT_URI}/api/external/get-notes", 
                                  json={
                                      "username": self.username,
                                      "password": self.password
                                  })
            
            if response.status_code == 200:
                data = response.json()
                
                for item in self.tree.get_children():
                    self.tree.delete(item)
                
                if isinstance(data, dict) and not data.get('success', True):
                    messagebox.showerror("Error", data.get('reason', 'Unknown error occurred'))
                    return
                
                for note in data:
                    last_changed = datetime.strptime(note['date_last_changed'], '%a, %d %b %Y %H:%M:%S GMT')
                    self.tree.insert("", "end", values=(note['id'], note['title'], 
                                   last_changed.strftime("%Y-%m-%d %H:%M")))
                    
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Failed to connect to server: {str(e)}")

    def show_add_note_dialog(self):
        NoteDialog(self, self.username, self.password)

    def show_edit_note_dialog(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        note_id = self.tree.item(selected_items[0])['values'][0]
        NoteDialog(self, self.username, self.password, note_id)

class NoteDialog:
    def __init__(self, parent, username, password, note_id=None):
        self.parent = parent
        self.username = username
        self.password = password
        self.note_id = note_id
        
        self.window = tk.Toplevel(parent)
        self.window.title("Edit Note" if note_id else "New Note")
        
        # Make it fullscreen
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        self.window.geometry(f"{screen_width}x{screen_height}+0+0")
        
        self.setup_ui()
        if note_id:
            self.load_note()

    def setup_ui(self):
        # Main container that fills the entire window
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        main_frame = ttk.Frame(self.window)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(1, weight=1)  # Make content row expandable
        main_frame.grid_columnconfigure(0, weight=1)  # Make column expandable

        # Title frame
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")
        title_frame.grid_columnconfigure(1, weight=1)  # Make title entry expandable
        
        ttk.Label(title_frame, text="Title:").grid(row=0, column=0, padx=(0, 5))
        self.title_var = tk.StringVar()
        ttk.Entry(title_frame, textvariable=self.title_var, font=("Helvetica", 12)).grid(row=0, column=1, sticky="ew")

        # Content frame
        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="nsew")
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)
        
        self.content_text = scrolledtext.ScrolledText(
            content_frame, 
            wrap=tk.WORD, 
            font=("Helvetica", 12)
        )
        self.content_text.grid(row=0, column=0, sticky="nsew")

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="e")
        
        ttk.Button(button_frame, text="Save", command=self.save_note).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.window.destroy).pack(side="right")

    def load_note(self):
        try:
            response = requests.post(f"{ROOT_URI}/api/external/get-note",
                                  json={
                                      "username": self.username,
                                      "password": self.password,
                                      "note-id": self.note_id
                                  })
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success', False):
                    note = data['note']
                    self.title_var.set(note['title'])
                    self.content_text.delete("1.0", tk.END)
                    self.content_text.insert("1.0", note['content'])
                else:
                    messagebox.showerror("Error", data.get('reason', 'Failed to fetch note'))
                    self.window.destroy()
            
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Failed to connect to server: {str(e)}")
            self.window.destroy()

    def save_note(self):
        try:
            if self.note_id is None:
                response = requests.post(f"{ROOT_URI}/api/external/add-note",
                                      json={
                                          "username": self.username,
                                          "password": self.password,
                                          "title": self.title_var.get(),
                                          "content": self.content_text.get("1.0", tk.END).strip()
                                      })
            else:
                response = requests.post(f"{ROOT_URI}/api/external/edit-note",
                                      json={
                                          "username": self.username,
                                          "password": self.password,
                                          "note-id": self.note_id,
                                          "title": self.title_var.get(),
                                          "content": self.content_text.get("1.0", tk.END).strip()
                                      })
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success', False):
                    messagebox.showinfo("Success", "Note saved successfully!")
                    self.parent.refresh_notes()
                    self.window.destroy()
                else:
                    messagebox.showerror("Error", data.get('reason', 'Failed to save note'))
            else:
                messagebox.showerror("Error", f"Server returned status code {response.status_code}")
                
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Failed to connect to server: {str(e)}")

def main():
    try:
        app = NotesApp()
        
        # Set minimum window size
        app.minsize(400, 300)
        
        # Handle window close
        def on_closing():
            if messagebox.askokcancel("Quit", "Do you want to quit?"):
                app.quit()
                
        app.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the application
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Application error: {str(e)}")

if __name__ == "__main__":
    main()
