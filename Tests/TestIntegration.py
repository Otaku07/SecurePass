import unittest
import sys
import os
from tkinter import Tk
import sqlite3
from unittest.mock import patch

# Ajout du chemin du répertoire 'src' au sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Src')))

# Import de la classe PasswordManagerApp depuis le script source
from SecurePassBy import PasswordManagerApp

class TestIntegrationPasswordManagerApp(unittest.TestCase):
    def setUp(self):
        # Initialiser l'application avec un contexte Tkinter
        self.root = Tk()
        self.app = PasswordManagerApp(self.root)

    @patch('sqlite3.connect')
    def test_full_user_flow(self, mock_connect):
        # Simuler une connexion à la base de données
        mock_conn = mock_connect.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.side_effect = [None, ('hashed_password',)]  # Simule un utilisateur non trouvé puis trouvé

        # Créer un compte
        self.app.show_create_account_screen()
        self.app.new_username_var.set('testuser')
        self.app.new_password_var.set('Password@123')
        self.app.confirm_password_var.set('Password@123')
        self.app.create_account()

        # Se connecter
        self.app.username_var.set('testuser')
        self.app.password_var.set('Password@123')
        self.app.login()

        # Ajouter un enregistrement
        self.app.site_entry.insert(0, 'TestSite')
        self.app.username_entry.insert(0, 'testuser')
        self.app.password_entry.insert(0, 'Password@123')
        self.app.save_record('TestSite', 'testuser', 'Password@123')

        # Valider que les actions ont été effectuées correctement
        calls = [
            unittest.mock.call.execute('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', unittest.mock.ANY),
            unittest.mock.call.execute('SELECT hashed_password FROM users WHERE username=?', ('testuser',)),
            unittest.mock.call.execute('INSERT INTO passwords (site_name, username_site, password) VALUES (?, ?, ?)', ('TestSite', 'testuser', 'Password@123'))
        ]
        mock_cursor.assert_has_calls(calls, any_order=True)

    def tearDown(self):
        self.app.root.destroy()

if __name__ == '__main__':
    unittest.main()
