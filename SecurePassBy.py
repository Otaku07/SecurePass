import os
import sqlite3
import base64
import secrets
from tkinter import messagebox, simpledialog, ttk, Label
import re
import tkinter as tk
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


# Constantes
ITERATIONS = 100000
SALT_SIZE = 32
DB_NAME = "SecurePassBy.db"


def generate_salt(size=SALT_SIZE):
    return secrets.token_bytes(size)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data.encode()).decode()

def user_exists(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    conn.close()

    return user is not None

def create_database():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users
            (username TEXT PRIMARY KEY, hashed_password TEXT, salt TEXT)
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords
            (username TEXT, site_name TEXT, username_site TEXT, password TEXT, salt TEXT)
        ''')

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass")
        self.root.geometry('900x500+50+50')
        self.countdown_window = None
        self.current_username = None
        self.encryption_key = None
        self.login_attempts = 0  # Add a counter for login attempts
        self.login_button = None
        self.waiting = False
        
        create_database()
        
        
        
        self.root.columnconfigure(0, weight=1)  # This makes column 0 (the only column) expandable
        self.head_title = Label(self.root, text="SecurePass Manager", font=("Arial",20), width="100",bg="blue", fg="white", padx="20", pady="20", justify="center")
        self.head_title.grid(columnspan=3)
        frame = tk.Frame(self.root)
        frame.grid(row=1, column=0)


        self.password_entry = tk.Entry(frame)  # Add a password entry field
        self.password_entry.pack()  # Display the password entry field
        self.username_entry = tk.Entry(frame)  # Create a text entry field for the username
        self.username_entry.pack()

        self.show_login_screen()
    
    @staticmethod
    def user_exists(username):
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
        return user is not None

    def clear_screen(self):
        
        for widget in self.root.winfo_children():
            # Don't destroy head_title
            if widget == self.head_title:
                continue
            widget.destroy()

    def show_login_screen(self):
        self.clear_screen()

        # Create a new frame to contain the login screen widgets
        self.login_frame = tk.Frame(self.root)
        self.login_frame.grid()

        # Add the widgets to the login_frame instead of self.root
        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.username_var = tk.StringVar()
        tk.Entry(self.login_frame, textvariable=self.username_var).grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        self.password_var = tk.StringVar()
        tk.Entry(self.login_frame, textvariable=self.password_var, show='*').grid(row=1, column=1, padx=10, pady=10)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)  # Store the login button in self.login_button
        self.login_button.grid(row=2, column=0, padx=10, pady=10)
        self.create_account_button = tk.Button(self.login_frame, text="Create Account", command=self.show_create_account_screen)
        self.create_account_button.grid(row=2, column=1, padx=10, pady=10)
        #tk.Button(login_frame, text="Create Account", command=self.show_create_account_screen).grid(row=2, column=1, padx=10, pady=10)
    
    def disable_login_interface(self, disable=True):
        """ Désactiver ou activer les éléments de l'interface de connexion """
        state = 'disabled' if disable else 'normal'
        # Désactiver tout le cadre de connexion
        for child in self.login_frame.winfo_children():
            # Utilise try-except pour éviter les erreurs si un widget ne peut pas être désactivé
            try:
                child.configure(state=state)
            except tk.TclError:
                pass



    def show_countdown(self, remaining=None):
        if self.waiting and remaining is None:
            return  # Prévenir les multiples comptes à rebours simultanés

        if remaining is not None:
            self.remaining = remaining

        if self.remaining <= 0:
            self.disable_login_interface(False)  # Réactiver l'interface de connexion
            if self.countdown_window is not None:
                self.countdown_window.destroy()
                self.countdown_window = None  # Important pour éviter de réutiliser une fenêtre détruite
            self.waiting = False
            self.username_var.set('')
            self.password_var.set('')
        else:
            if self.countdown_window is None:  # Créer la fenêtre si elle n'existe pas déjà
                self.countdown_window = tk.Toplevel(self.root)
                self.countdown_window.protocol("WM_DELETE_WINDOW", self.force_close_application)  # Désactiver la fermeture via la croix
                self.countdown_label = tk.Label(self.countdown_window, text="")
                self.countdown_label.pack()

            # Mettre à jour le texte du compte à rebours
            if self.countdown_window.winfo_exists() and self.countdown_label.winfo_exists():
                self.countdown_label.config(text=f"Vous vous êtes trompé trois fois. Pour vous connecter merci d'attendre {self.remaining} secondes")
            self.remaining -= 1
            self.root.after(1000, self.show_countdown)
            
    def force_close_application(self):
        """ Force la fermeture de l'application """
        self.root.destroy()


    def login(self):
        username = self.username_var.get()
        password = self.password_var.get().encode('utf-8')  # Convertir le mot de passe en bytes
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT hashed_password FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            if not self.user_exists(username):
                messagebox.showerror("Erreur", "Utilisateur introuvable, veuillez réessayer")
                self.username_var.set('')
                self.password_var.set('')
                return
            if user:
                hashed_password = user[0].encode('utf-8')  # Convertir le hash du mot de passe en bytes
                if bcrypt.checkpw(password, hashed_password):  # Utiliser bcrypt.checkpw pour vérifier le mot de passe
                # Le reste de votre logique de connexion
                    self.current_username = username
                    self.encryption_key = Fernet.generate_key()
                    self.show_main_menu()
                else:
                    if self.waiting:
                        return  # Do not process login attempts while waiting

                    self.login_attempts += 1
                    if self.login_attempts >= 3:
                        self.disable_login_interface(True)  # Désactiver l'interface login
                        self.show_countdown(300)  # Start a 5 minute countdown
                        self.login_attempts = 0  # Reset attempts after triggering countdown
                    else:
                        messagebox.showerror("Echec de connexion", "Mot de passe incorrect. Merci de réessayer.")
                        self.username_var.set('')
                        self.password_var.set('')
            
    def show_create_account_screen(self):
        
        self.clear_screen()
        tk.Label(self.root, text="Username:").grid(row=0, column=0)
        self.new_username_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.new_username_var).grid(row=0, column=1)

        tk.Label(self.root, text="Password:").grid(row=1, column=0)
        self.new_password_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.new_password_var, show='*').grid(row=1, column=1)

        tk.Label(self.root, text="Confirm Password:").grid(row=2, column=0)
        self.confirm_password_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.confirm_password_var, show='*').grid(row=2, column=1)

        tk.Button(self.root, text="Create Account", command=self.create_account).grid(row=5, column=0, columnspan=2)

    def create_account(self):
        username = self.new_username_var.get()
        password = self.new_password_var.get()
        confirm_password = self.confirm_password_var.get()
      
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{14,}$', password):
            messagebox.showerror("Error", "Password does not meet complexity requirements")
            return

        salt = generate_salt()
        #key = derive_key(password, salt)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                            (username, hashed_password.decode('utf-8'), salt))  # Store the hashed password as a string
                messagebox.showinfo("Success", "Account created successfully")
                self.show_login_screen()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
            
    def show_main_menu(self):
        self.clear_screen()
        tk.Button(self.root, text="Add Password", command=self.add_password_ui).grid(row=0, column=0)
        tk.Button(self.root, text="View Passwords", command=self.view_passwords).grid(row=1, column=0)
        tk.Button(self.root, text="Delete Password", command=self.delete_password_ui).grid(row=2, column=0)
        tk.Button(self.root, text="Logout", command=self.logout).grid(row=3, column=0)

    def add_password_ui(self):
        self.clear_screen()
        tk.Label(self.root, text="ID Securepass:").grid(row=0, column=0)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.grid(row=0, column=1)
        tk.Label(self.root, text="Nom du site:").grid(row=1, column=0)
        self.site_name_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.site_name_var).grid(row=1, column=1)
        tk.Label(self.root, text="Username du site:").grid(row=2, column=0)
        self.site_username_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.site_username_var).grid(row=2, column=1)
        tk.Label(self.root, text="Mot de passe:").grid(row=3, column=0)
        self.site_password_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.site_password_var).grid(row=3, column=1)
        tk.Button(self.root, text="Add", command=self.add_password).grid(row=4, column=0, columnspan=2)
        tk.Button(self.root, text="Return", command=self.show_main_menu).grid(row=5, column=0, columnspan=2)
    
    def add_password(self):
        username = self.username_entry.get()
        site_name = self.site_name_var.get()
        username_site = self.site_username_var.get()
        password = self.site_password_var.get()
        salt = generate_salt()
        key = derive_key(password, salt)
        encrypted_password = encrypt_data(password, key)

        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO passwords (username, site_name, username_site, password, salt) VALUES (?, ?, ?, ?, ?)",
                            (username, site_name, username_site, encrypted_password, salt))
                messagebox.showinfo("Success", "Password added successfully")
                self.username_entry.delete(0, 'end')
                self.site_name_var.set('')
                self.site_username_var.set('')
                self.site_password_var.set('')
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Failed to add password")
            self.show_main_menu()

    def view_passwords(self):
        self.clear_screen()
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT site_name, username_site, password FROM passwords WHERE username=?", (self.current_username,))
            rows = cursor.fetchall()
            if rows:
                for i, (site_name, username_site, password) in enumerate(rows, start=1):
                    fernet = Fernet(self.encryption_key)
                    decrypted_password = fernet.decrypt(password.encode()).decode()
                    tk.Label(self.root, text=f"{site_name} - {username_site} - {decrypted_password}").grid(row=i, column=0)
            else:
                tk.Label(self.root, text="No passwords saved").grid(row=0, column=0)
        tk.Button(self.root, text="Back", command=self.show_main_menu).grid(row=len(rows) + 1, column=0)

    def delete_password_ui(self):
        self.clear_screen()
        tk.Label(self.root, text="Site Name:").grid(row=0, column=0)
        self.delete_site_name_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.delete_site_name_var).grid(row=0, column=1)
        tk.Button(self.root, text="Delete", command=self.delete_password).grid(row=1, column=0, columnspan=2)

    def delete_password(self):
        site_name = self.delete_site_name_var.get()
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE username=? AND site_name=?", (self.current_username, site_name))
            if cursor.rowcount > 0:
                messagebox.showinfo("Success", "Password deleted successfully")
            else:
                messagebox.showerror("Error", "No such site found")
            self.show_main_menu()

    def logout(self):
        self.current_username = None
        self.encryption_key = None
        self.show_login_screen()

def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
