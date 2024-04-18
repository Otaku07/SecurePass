import os
import sqlite3
import base64
import secrets
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import re
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, Label


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

def create_database():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users
            (username TEXT PRIMARY KEY, hashed_password TEXT, salt TEXT, secret_question TEXT, secret_answer TEXT)
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
        #self.password_entry = tk.Entry(self.root)  # Add a password entry field
        #self.password_entry.pack()  # Display the password entry field
        #self.username_entry = tk.Entry(self.root)  # Create a text entry field for the username
        #self.username_entry.pack()
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

    def clear_screen(self):
        
        for widget in self.root.winfo_children():
            # Don't destroy head_title
            if widget == self.head_title:
                continue
            widget.destroy()

    def show_login_screen(self):
        self.clear_screen()

        # Create a new frame to contain the login screen widgets
        login_frame = tk.Frame(self.root)
        login_frame.grid()

        # Add the widgets to the login_frame instead of self.root
        tk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.username_var = tk.StringVar()
        tk.Entry(login_frame, textvariable=self.username_var).grid(row=0, column=1, padx=10, pady=10)

        tk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        self.password_var = tk.StringVar()
        tk.Entry(login_frame, textvariable=self.password_var, show='*').grid(row=1, column=1, padx=10, pady=10)

        self.login_button = tk.Button(login_frame, text="Login", command=self.login)  # Store the login button in self.login_button
        self.login_button.grid(row=2, column=0, padx=10, pady=10)
        tk.Button(login_frame, text="Create Account", command=self.show_create_account_screen).grid(row=2, column=1, padx=10, pady=10)
    
    def show_countdown(self, remaining=None):
        if remaining is not None:
            self.remaining = remaining

        if self.remaining <= 0:
                self.countdown_window.destroy()
                self.show_secret_question_screen()
        else:
            if not hasattr(self, 'countdown_window'):
                self.countdown_window = tk.Toplevel(self.root)
                self.countdown_window.protocol("WM_DELETE_WINDOW", self.root.quit)
                self.countdown_label = tk.Label(self.countdown_window)
                self.countdown_label.pack()
            self.countdown_label.config(text="Vous vous êtes trompé trois fois. Pour vous connecter merci d'attendre %d secondes" % self.remaining)
            self.remaining = self.remaining - 1
            self.root.after(1000, self.show_countdown)
  
    def ask_secret_question(self):
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT secret_question, secret_answer FROM users WHERE username=?", (self.username_var.get(),))
            secret_question, secret_answer = cursor.fetchone()
            user_answer = simpledialog.askstring("Secret Question", secret_question, parent=self.root)
            if user_answer != secret_answer:
                messagebox.showerror("Login failed", "Incorrect answer. The application will now close.")
                self.root.destroy()
            else:
                messagebox.showinfo("Login", "Correct answer. You can now try to login again.")
                self.login_attempts = 0  # Reset the counter if the answer is correct
                self.show_login_screen()


    def login(self):
        username = self.username_var.get()
        password = self.password_var.get().encode('utf-8')  # Convertir le mot de passe en bytes
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT hashed_password FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            if user:
                hashed_password = user[0].encode('utf-8')  # Convertir le hash du mot de passe en bytes
                if bcrypt.checkpw(password, hashed_password):  # Utiliser bcrypt.checkpw pour vérifier le mot de passe
                # Le reste de votre logique de connexion
                    self.current_username = username
                    self.encryption_key = Fernet.generate_key()
                    self.show_main_menu()
                    self.login_attempts = 0  # Reset the counter if the login is successful
                else:
                    self.login_attempts += 1
                    if self.login_attempts >= 3 and not self.waiting:
                        self.waiting = True
                        self.login_button.config(state="disabled")  # Disable the login button
                        self.show_countdown(120)  # Show a countdown of 2 minutes
                    else:
                        messagebox.showerror("Login failed", "Incorrect password")
            else:
                messagebox.showerror("Login failed", "User not found")

                
    def show_secret_question_screen(self):
        self.waiting = False
        self.new_window = tk.Toplevel(self.root)
        self.new_window.protocol("WM_DELETE_WINDOW", self.root.quit)  # Bind the "delete window" event to a function that quits the program
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT secret_question FROM users WHERE username=?", (self.username_var.get(),))
            secret_question = cursor.fetchone()[0]
        tk.Label(self.new_window, text=secret_question).grid(row=0, column=0)
        self.secret_answer_entry = tk.Entry(self.new_window)
        self.secret_answer_entry.grid(row=1, column=0)
        self.secret_answer_button = tk.Button(self.new_window, text="Submit answer", command=self.check_secret_question_answer)
        self.secret_answer_button.grid(row=2, column=0)
           
    def check_secret_question_answer(self):
        user_answer = self.secret_answer_entry.get()
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT secret_answer FROM users WHERE username=?", (self.username_var.get(),))
            correct_answer = cursor.fetchone()[0]
        if user_answer == correct_answer:
            self.login_attempts = 0  # Reset the counter if the answer is correct
            self.waiting = False
            self.new_window.destroy()  # Close the secret question window
            self.login_button.config(state="normal")  # Enable the login button
            self.show_login_screen()
        else:
            messagebox.showerror("Incorrect answer", "Incorrect answer. The program will now exit.")
            self.root.quit()  # Exit the program
            
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

        tk.Label(self.root, text="Secret Question:").grid(row=3, column=0)
        self.secret_question_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.secret_question_var).grid(row=3, column=1)

        tk.Label(self.root, text="Secret Answer:").grid(row=4, column=0)
        self.secret_answer_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.secret_answer_var).grid(row=4, column=1)

        tk.Button(self.root, text="Create Account", command=self.create_account).grid(row=5, column=0, columnspan=2)

    def create_account(self):
        username = self.new_username_var.get()
        password = self.new_password_var.get()
        confirm_password = self.confirm_password_var.get()
        secret_question = self.secret_question_var.get()
        secret_answer = self.secret_answer_var.get()

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
                cursor.execute("INSERT INTO users (username, hashed_password, salt, secret_question, secret_answer) VALUES (?, ?, ?, ?, ?)",
                            (username, hashed_password.decode('utf-8'), salt, secret_question, secret_answer))  # Store the hashed password as a string
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
