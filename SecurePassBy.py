import os
import sqlite3
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import secrets
import hashlib
import re
import time
import tkinter as tk
from tkinter import messagebox

# Constantes
ITERATIONS = 100000
SALT_SIZE = 32

def generate_salt(size=SALT_SIZE):
    return secrets.token_bytes(size)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=ITERATIONS,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def create_database(db_name):
     conn = sqlite3.connect(db_name)
     cursor = conn.cursor()
    
     cursor.execute('''
        CREATE TABLE IF NOT EXISTS users
        (username TEXT PRIMARY KEY, hashed_password TEXT, salt TEXT, secret_question TEXT, secret_answer TEXT)
    ''')
     cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords
        (username TEXT, site_name TEXT, username_site TEXT, password TEXT, salt BLOB)
    ''')
     conn.commit()
     conn.close()

def store_in_database(db_name, username, hashed_password, salt, secret_question, secret_answer):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (username, hashed_password, salt, secret_question, secret_answer)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, sqlite3.Binary(hashed_password), sqlite3.Binary(salt), secret_question, secret_answer))
    conn.commit()
    conn.close()

def retrieve_secret_answer(db_name, username):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT secret_answer FROM users WHERE username = ?
    ''', (username,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        raise Exception("Utilisateur non identifié")
    return row[0]

def retrieve_from_database(db_name, username):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT hashed_password, salt, secret_question, secret_answer FROM users WHERE username = ?
    ''', (username,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None, None, None, None
    return bytes(row[0]), bytes(row[1]), row[2], row[3]

def add_password(db_name, username, key):
    site_name = input("Nom du site : ")
    username_site = input("Nom d'utilisateur : ")
    password = getpass.getpass("Mot de passe : ")

    salt = generate_salt()
    hashed_password = Fernet(key).encrypt(password.encode())

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO passwords (username, site_name, username_site, password, salt)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, site_name, username_site, sqlite3.Binary(hashed_password), sqlite3.Binary(salt)))
    conn.commit()
    conn.close()
    print("Entrée ajoutée avec succès !")

def delete_password(db_name, username):
    # Demandez à l'utilisateur de prouver son identité
    password = getpass.getpass("Pour supprimer un mot de passe, veuillez confirmer votre identité en entrant votre mot de passe : ")
    hashed_password, salt, _, _ = retrieve_from_database(db_name, username)

    if derive_key(password, salt) != hashed_password:
        print("Mot de passe incorrect. Suppression annulée.")
        return

    # Récupérez la liste des sites enregistrés pour l'utilisateur
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT site_name FROM passwords WHERE username = ?
    ''', (username,))
    sites = cursor.fetchall()

    # Affichez la liste des sites et demandez à l'utilisateur de choisir un site
    print("Voici la liste de vos sites enregistrés :")
    for i, site in enumerate(sites, start=1):
        print(f"{i}. {site[0]}")

    site_choice = input("Entrez le numéro du site pour lequel vous souhaitez supprimer le mot de passe : ")
    site_name = sites[int(site_choice) - 1][0]

    # Supprimez le mot de passe pour le site choisi
    cursor.execute('''
        DELETE FROM passwords WHERE username = ? AND site_name = ?
    ''', (username, site_name))
    conn.commit()
    conn.close()

    print("Le mot de passe a été supprimé avec succès.")

def hash_password(password):
    # Génère un sel aléatoire
    salt = os.urandom(16)
    # Hache le mot de passe avec le sel
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed_password, salt

def view_passwords(db_name, username, encryption_key):
    hashed_password, salt, _, _ = retrieve_from_database(db_name, username)
    # Le reste du code reste le même:
    password = getpass.getpass("Entrez à nouveau votre mot de passe de connexion pour vérification : ")
    reponse_secrete = input("Réponse à votre question secrète : ")
    hashed_password, salt, _, _ = retrieve_from_database(db_name, username)
    if hashed_password is None or derive_key(password, salt) != hashed_password or reponse_secrete != retrieve_secret_answer(db_name, username):
        print("Mot de passe ou réponse secrète invalide")
    else:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT site_name, username_site, password, salt FROM passwords WHERE username = ?
        ''', (username,))
        rows = cursor.fetchall()
        conn.close()

        print("Nom du site\tNom d'utilisateur\tMot de passe")
        for row in rows:
            decrypted_password = Fernet(encryption_key).decrypt(bytes(row[2]))
            print(f"{row[0]}\t{row[1]}\t{decrypted_password.decode()}")


secret_questions = [
    "Quel est le nom de la première rue dans laquelle vous avez habité ?",
    "Quel est votre plat préféré ?",
    "Quel est le nom de votre premier animal de compagnie ?",
    "Quel est le nom de votre équipe sportive préférée ?",
    "Quel est votre loisir préféré ?",
    "Quel est le prénom de votre premier amour ?",
    "Quel est le nom de votre film préféré ?",
    "Quel est le prénom de votre grand-père / grand-mère maternelle / paternelle  ?",
    "Où avez-vous rencontré votre partenaire actuel ?",
    "Quelle est la marque de votre premier téléphone portable ?"
]

def create_account(db_name):
    def submit_form():
        username = username_entry.get()
        password = password_entry.get()
        password_confirm = password_confirm_entry.get()

        # Vérifie si le nom d'utilisateur existe déjà
        existing_hashed_password, _ = retrieve_from_database(db_name, username)
        if existing_hashed_password is not None:
            messagebox.showerror("Erreur", "Ce nom d'utilisateur existe déjà. Veuillez en choisir un autre.")
            return

        if password != password_confirm:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas. Veuillez réessayer.")
            return

        # Vérifie si le mot de passe respecte le format requis
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{14,}$', password):
            messagebox.showerror("Erreur", "Le mot de passe ne respecte pas le format requis. Veuillez réessayer.")
            return

        secret_question = secret_question_var.get()
        secret_answer = secret_answer_entry.get()

        salt = generate_salt()
        hashed_password = derive_key(password, salt)

        store_in_database(db_name, username, hashed_password, salt, secret_question, secret_answer)
        messagebox.showinfo("Succès", "Compte créé avec succès !")
        window.destroy()

    window = tk.Tk()
    window.title("Créer un compte")

    username_label = tk.Label(window, text="Nom d'utilisateur")
    username_entry = tk.Entry(window)
    password_label = tk.Label(window, text="Mot de passe")
    password_entry = tk.Entry(window, show="*")
    password_confirm_label = tk.Label(window, text="Confirmez le mot de passe")
    password_confirm_entry = tk.Entry(window, show="*")
    secret_question_label = tk.Label(window, text="Question secrète")
    secret_question_var = tk.StringVar(window)
    secret_question_var.set("Choisissez une question secrète")
    secret_question_optionmenu = tk.OptionMenu(window, secret_question_var, *secret_questions)
    secret_answer_label = tk.Label(window, text="Réponse secrète")
    secret_answer_entry = tk.Entry(window)
    submit_button = tk.Button(window, text="Soumettre", command=submit_form)

    username_label.pack()
    username_entry.pack()
    password_label.pack()
    password_entry.pack()
    password_confirm_label.pack()
    password_confirm_entry.pack()
    secret_question_label.pack()
    secret_question_optionmenu.pack()
    secret_answer_label.pack()
    secret_answer_entry.pack()
    submit_button.pack()

    window.mainloop()


def login(db_name):
    username = input("Entrez votre nom d'utilisateur : ")
    hashed_password, salt, secret_question, secret_answer = retrieve_from_database(db_name, username)

    if hashed_password is None:
        print("Ce nom d'utilisateur n'existe pas.")
        return

    attempts = 0
    while attempts < 3:
        password = getpass.getpass("Entrez votre mot de passe : ")

        if derive_key(password, salt) == hashed_password:
            print("Connexion réussie !")
            encryption_key = derive_key(password, salt)

            while True:
                print("\nOptions:")
                print("1. Ajouter un nouveau mot de passe")
                print("2. Afficher tous les mots de passe")
                print("3. Supprimer un mot de passe")
                print("4. Se déconnecter")
                choice = input("Entrez votre choix : ")

                if choice == "1":
                    add_password(db_name, username, encryption_key)
                elif choice == "2":
                    view_passwords(db_name, username, encryption_key)
                elif choice == "3":
                    delete_password(db_name, username)
                elif choice == "4":
                    print("Déconnexion réussie !")
                    break
                else:
                    print("Choix invalide. Veuillez réessayer !")
            return

        print("Mot de passe incorrect. Veuillez réessayer.")
        attempts += 1

    print("Vous avez échoué 3 tentatives de connexion. Veuillez attendre 2 minutes avant de réessayer.")
    time.sleep(120)  # Attendre 2 minutes

    print(f"Question secrète : {secret_question}")
    user_answer = input("Entrez votre réponse : ")

    if user_answer != secret_answer:
        print("La réponse est incorrecte. La connexion a échoué.")
        return

    print("Réponse correcte. Vous pouvez maintenant vous connecter à nouveau.")
                
def main():
    db_name = "securepass.db"
    create_database(db_name)

    while True:
        print("\nOptions:")
        print("1. Create a new account")
        print("2. Login")
        print("3. Quit")
        choice = input("Enter your choice: ")

        if choice == "1":
            create_account(db_name)
        elif choice == "2":
            login(db_name)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again!")

if __name__ == "__main__":
    main()