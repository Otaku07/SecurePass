import sqlite3
import base64
import secrets
from tkinter import messagebox, ttk, Label
import re
import tkinter as tk
import bcrypt
#import cryptography.fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
#import cryptography


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
            CREATE TABLE IF NOT EXISTS users (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            hashed_password TEXT,
            salt TEXT)
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            site_name TEXT,
            username_site TEXT,
            password TEXT,
            salt TEXT,
            FOREIGN KEY(user_id) REFERENCES users(ID))
        ''')

class PasswordManagerApp:
    conn = None
    def __init__(self, root):
        self.root = root
        if PasswordManagerApp.conn is None:
            PasswordManagerApp.conn = sqlite3.connect(DB_NAME)
        self.root.title("SecurePass Manager")
        self.root.geometry('900x540+100+100')
        #self.root.configure(bg=BG_COLOR)
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
        tk.Label(self.login_frame, text="Username:", font=('Arial', 12, 'bold')).grid(row=0, column=0, padx=20, pady=15)
        self.username_var = tk.StringVar()
        tk.Entry(self.login_frame, textvariable=self.username_var, bd=2, relief='solid').grid(row=0, column=1, padx=20, pady=15)

        tk.Label(self.login_frame, text="Password:", font=('Arial', 12, 'bold')).grid(row=1, column=0, padx=20, pady=15)
        self.password_var = tk.StringVar()
        tk.Entry(self.login_frame, textvariable=self.password_var, bd=2, relief='solid', show='*').grid(row=1, column=1, padx=20, pady=15)

        self.login_button = tk.Button(self.login_frame, text="Login", bg='blue', fg='white', font=('Arial', 12, 'bold'), command=self.login)  # Store the login button in self.login_button
        self.login_button.grid(row=2, column=0, padx=10, pady=10)
        self.create_account_button = tk.Button(self.login_frame, text="Create Account", bg='blue', fg='white', font=('Arial', 12, 'bold'), command=self.show_create_account_screen)
        self.create_account_button.grid(row=2, column=1, padx=10, pady=10)
    
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
        password = self.password_var.get().encode('utf-8')
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ID, hashed_password FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            if user:
                user_id, hashed_password = user
                if bcrypt.checkpw(password, hashed_password.encode('utf-8')):
                    self.current_username = username
                    self.current_user_id = user_id  # Stocker l'ID de l'utilisateur
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
                        messagebox.showerror("Echec de connexion", "Mot de passe ou non d'utilisateur incorrect. Merci de réessayer.")
                        self.username_var.set('')
                        self.password_var.set('')
            else:
                messagebox.showerror("Echec de connexion", "Mot de passe ou non d'utilisateur incorrect. Merci de réessayer.")
                self.username_var.set('')
                self.password_var.set('')
            
    def show_create_account_screen(self):
        self.clear_screen()

        # Utiliser un cadre central pour aligner les widgets au centre
        create_account_frame = tk.Frame(self.root)
        create_account_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Champ Username
        tk.Label(create_account_frame, text="Username:", font=("Arial", 12, 'bold'), fg='black').grid(row=1, column=0, sticky='e', padx=20, pady=15)
        self.new_username_var = tk.StringVar()
        username_entry = tk.Entry(create_account_frame, textvariable=self.new_username_var, font=("Arial", 12), bd=2, relief='solid')
        username_entry.grid(row=1, column=1, padx=20, pady=15)

        # Champ Password
        tk.Label(create_account_frame, text="Password:", font=("Arial", 12, 'bold'), fg='black').grid(row=2, column=0, sticky='e', padx=20, pady=15)
        self.new_password_var = tk.StringVar()
        password_entry = tk.Entry(create_account_frame, textvariable=self.new_password_var, show='*', font=("Arial", 12), bd=2, relief='solid')
        password_entry.grid(row=2, column=1, padx=20, pady=15)

        # Champ Confirm Password
        tk.Label(create_account_frame, text="Confirm Password:", font=("Arial", 12, 'bold'), fg='black').grid(row=3, column=0, sticky='e', padx=20, pady=15)
        self.confirm_password_var = tk.StringVar()
        confirm_password_entry = tk.Entry(create_account_frame, textvariable=self.confirm_password_var, show='*', font=("Arial", 12), bd=2, relief='solid')
        confirm_password_entry.grid(row=3, column=1, padx=10, pady=10)

        # Boutons
        create_btn = tk.Button(create_account_frame, text="Create Account", font=("Arial", 12, 'bold'), command=self.create_account, bg='blue', fg='white')
        create_btn.grid(row=4, column=1, padx=10, pady=10, sticky='e')

        cancel_btn = tk.Button(create_account_frame, text="Cancel", font=("Arial", 12, 'bold'), command=self.show_login_screen, bg='blue', fg='white')
        cancel_btn.grid(row=4, column=0, padx=10, pady=10, sticky='e')

        # Mettre le focus sur le champ Username à l'ouverture
        username_entry.focus_set()


    def create_account(self):
        username = self.new_username_var.get()
        password = self.new_password_var.get()
        confirm_password = self.confirm_password_var.get()
      
        if password != confirm_password:
            messagebox.showerror("Error", "Mots de passe non identiques!")
            return


        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{14,}$', password):
            messagebox.showerror("Error", "Le mot de passe doit contenir au moins 14 caractères, une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial.")
            return

        salt = generate_salt()
        #key = derive_key(password, salt)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                            (username, hashed_password.decode('utf-8'), salt))  # Store the hashed password as a string
                messagebox.showinfo("Success", "Compte créé avec succès!")

        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "L'utilisateur existe déjà")
            
        self.show_login_screen()
            
    
    def show_main_menu(self):
        self.clear_screen()
        # Utilisation d'une grille pour une meilleure disposition
        entry_frame = tk.Frame(self.root)
        entry_frame.grid(row=1, padx=20, pady=20, sticky="ew")

        # Configuration de la grille pour qu'elle s'étire de manière égale
        entry_frame.columnconfigure(0, weight=1)
        entry_frame.columnconfigure(1, weight=1)
        entry_frame.columnconfigure(2, weight=1)
        entry_frame.columnconfigure(3, weight=1)
        entry_frame.columnconfigure(4, weight=1)  # Pour le bouton de recherche si nécessaire

        # Labels et champs de saisie
        tk.Label(entry_frame, text="Site Name").grid(row=0, column=0, sticky='ew')
        self.site_entry = tk.Entry(entry_frame)
        self.site_entry.grid(row=1, column=0, sticky='ew', padx=5)

        tk.Label(entry_frame, text="Username").grid(row=0, column=1, sticky='ew')
        self.username_entry = tk.Entry(entry_frame)
        self.username_entry.grid(row=1, column=1, sticky='ew', padx=5)

        tk.Label(entry_frame, text="Password").grid(row=0, column=2, sticky='ew')
        self.password_entry = tk.Entry(entry_frame, show='*')
        self.password_entry.grid(row=1, column=2, sticky='ew', padx=5)

        tk.Label(entry_frame, text="Search").grid(row=0, column=3, sticky='ew')
        self.search_entry = tk.Entry(entry_frame)
        self.search_entry.grid(row=1, column=3, sticky='ew', padx=5)
        self.search_entry.bind('<KeyRelease>', self.dynamic_search)

        # Boutons de gestion des enregistrements
        
        tk.Button(entry_frame, text="Save", bg='blue', fg='white', font=('Arial', 12, 'bold'), command=self.save_record).grid(row=2, column=0, padx=15, pady=5)
        tk.Button(entry_frame, text="Update", bg='blue', fg='white', font=('Arial', 12, 'bold'), command=self.update_record).grid(row=2, column=1, padx=15, pady=5)
        tk.Button(entry_frame, text="Delete", bg='blue', fg='white', font=('Arial', 12, 'bold'), command=self.delete_record).grid(row=2, column=2, padx=15, pady=5)

        # Affichage des enregistrements
        records_frame = tk.Frame(self.root)
        records_frame.grid(row=3, padx=20, pady=20, sticky="nsew")
        self.records_tree = ttk.Treeview(records_frame, columns=("Site Name", "Username", "Password"), show="headings")
        self.records_tree.heading("Site Name", text="Site Name")
        self.records_tree.heading("Username", text="Username")
        self.records_tree.heading("Password", text="Password")
        self.records_tree.pack(fill=tk.BOTH, expand=True)
        self.records_tree.bind('<<TreeviewSelect>>', self.on_record_select)


        # Bouton de déconnexion
        logout_button = tk.Button(self.root, text="Logout", bg='blue', fg='white', font=('Arial', 12, 'bold'), command=self.logout)
        logout_button.grid(row=4, pady=10)

        self.load_records()
        
    def load_records(self):
        self.records_tree.delete(*self.records_tree.get_children())  # Clear previous entries
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ID, site_name, username_site, password FROM passwords WHERE user_id=? ORDER BY ID", (self.current_user_id,))
            records = cursor.fetchall()
            for record in records:
                record_id, site_name, username, password = record
                # Insert data with ID as 'iid'
                self.records_tree.insert("", "end", iid=record_id, values=(site_name, username, password))

    def save_record(self):
        website = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if website and username and password:  # Vérification que les champs ne sont pas vides
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO passwords (user_id, site_name, username_site, password) VALUES (?, ?, ?, ?)",
                            (self.current_user_id, website, username, password))
                conn.commit()  # Appliquer les changements dans la base de données
            self.load_records()  # Recharger les enregistrements pour afficher le nouveau
        else:
            messagebox.showwarning("Warning", "Tous les champs sont requis!")
        
        # Effacer les champs après enregistrement
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

        
    def on_record_select(self, event):
        selected = self.records_tree.selection()
        if selected:
            record = self.records_tree.item(selected[0], 'values')
            # Effacer le contenu actuel dans les champs
            self.site_entry.delete(0, tk.END)
            self.site_entry.insert(0, record[0])
            self.username_entry.delete(0, tk.END)
            self.username_entry.insert(0, record[1])
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, record[2])
            
    def update_record(self):
        selected_items = self.records_tree.selection()
        if selected_items:
            selected_item = selected_items[0]
            # L'iid est l'identifiant de l'élément dans le Treeview
            real_id = selected_item  # l'iid est directement l'ID de la base de données
            site = self.site_entry.get()
            username = self.username_entry.get()
            password = self.password_entry.get()

            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE passwords SET site_name=?, username_site=?, password=? WHERE ID=?",
                            (site, username, password, real_id))
                conn.commit()

            self.load_records()
            
                # Effacer les champs après enregistrement
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def delete_record(self):
        selected_items = self.records_tree.selection()
        if selected_items:
            selected_item = selected_items[0]
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM passwords WHERE ID=? AND user_id=?", (selected_item, self.current_user_id))
                conn.commit()
            self.load_records()


                # Effacer les champs après enregistrement
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)


    def dynamic_search(self, event):
        search_term = self.search_entry.get().strip().lower()
        if search_term:
            # Si le terme de recherche n'est pas vide, filtrer les items
            visible_items = []
            for item in self.records_tree.get_children():
                item_values = self.records_tree.item(item, "values")
                if search_term in " ".join(map(str, item_values)).lower():
                    visible_items.append(item_values)  # Stocker les valeurs de l'élément, pas l'élément lui-même
            # Mettre à jour l'affichage pour montrer uniquement les éléments correspondants
            self.records_tree.delete(*self.records_tree.get_children())  # Supprime tous les éléments
            for item_values in visible_items:
                self.records_tree.insert('', 'end', values=item_values, tags='matched')
        else:
            # Recharger tous les enregistrements de la base de données lorsque la recherche est vide
            self.load_records()

        # Mettre à jour les couleurs pour les items correspondants
        self.records_tree.tag_configure('matched', background='yellow')



    def logout(self):
        
        # Réinitialisation des informations de session de l'utilisateur
        self.current_username = None
        self.encryption_key = None

        # Effacement des champs de saisie
        if hasattr(self, 'username_var') and hasattr(self, 'password_var'):
            self.username_var.set('')
            self.password_var.set('')

        # Affichage de l'écran de connexion
        self.show_login_screen()

        # Message de confirmation de la déconnexion en français
        messagebox.showinfo("Déconnexion réussie", "Vous avez été déconnecté avec succès.")

    
def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()