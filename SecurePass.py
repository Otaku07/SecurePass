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
        SELECT hashed_password, salt FROM users WHERE username = ?
    ''', (username,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None, None
    return bytes(row[0]), bytes(row[1])

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

def hash_password(password):
    # Génère un sel aléatoire
    salt = os.urandom(16)
    # Hache le mot de passe avec le sel
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed_password, salt

def view_passwords(db_name, username, key):
    password = getpass.getpass("Entrez à nouveau votre mot de passe de connexion pour vérification : ")
    reponse_secrete = input("Réponse à votre question secrète : ")
    hashed_password, salt = retrieve_from_database(db_name, username)
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
            decrypted_password = Fernet(key).decrypt(bytes(row[2]))
            print(f"{row[0]}\t{row[1]}\t{decrypted_password.decode()}")

def create_account(db_name):
    username = input("Entrez votre nom d'utilisateur : ")

    # Vérifie si le nom d'utilisateur existe déjà
    existing_hashed_password, _ = retrieve_from_database(db_name, username)
    if existing_hashed_password is not None:
        print("Ce nom d'utilisateur existe déjà. Veuillez en choisir un autre.")
        return

    password = getpass.getpass("Entrez votre mot de passe : ")
    secret_question = input("Entrez votre question secrète : ")
    secret_answer = input("Entrez votre réponse secrète : ")

    hashed_password, salt = hash_password(password)

    store_in_database(db_name, username, hashed_password, salt, secret_question, secret_answer)
    print("Compte créé avec succès !")

def login(db_name):
    username = input("Entrez votre nom d'utilisateur : ")
    password = getpass.getpass("Entrez votre mot de passe : ")
    hashed_password, salt = retrieve_from_database(db_name, username)
    if hashed_password is None or derive_key(password, salt) != hashed_password:
        print("Nom d'utilisateur ou mot de passe invalide")
    else:
        print("Connexion réussie")
        encryption_key = derive_key(password, salt)
        while True:
            print("\nOptions:")
            print("1. Ajouter un nouveau mot de passe")
            print("2. Afficher tous les mots de passe")
            print("3. Se déconnecter")
            choice = input("Entrez votre choix : ")

            if choice == "1":
                add_password(db_name, username, encryption_key)
            elif choice == "2":
                view_passwords(db_name, username, encryption_key)
            elif choice == "3":
                print("Déconnexion réussie !")
                break
            else:
                print("Choix invalide. Veuillez réessayer !")
                
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