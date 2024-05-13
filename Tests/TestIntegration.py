import unittest
import tkinter as tk
#from your_password_manager_module import PasswordManagerApp, create_database
import os
import sys
sys.path.append(os.path.abspath('../Src'))  # Assurez-vous que le chemin est correct

from SecurePassBy import PasswordManagerApp, create_database,DB_NAME



class TestPasswordManagerApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup the database and the environment before all tests
        cls.db_name = DB_NAME
        if os.path.exists(cls.db_name):
            os.remove(cls.db_name)
        create_database()  # Ensure the database is set up

    def setUp(self):
        # Setup the application before each test
        self.root = tk.Tk()
        self.app = PasswordManagerApp(self.root)

    def test_create_account(self):
        # Simulate account creation
        self.app.show_create_account_screen()
        self.app.new_username_var.set("testuser")
        self.app.new_password_var.set("Testpassword1!")
        self.app.confirm_password_var.set("Testpassword1!")
        self.app.create_account()
        self.assertTrue(self.app.user_exists("testuser"))

    def test_login_success(self):
        # Simulate successful login
        self.test_create_account()  # First create an account
        self.app.show_login_screen()
        self.app.username_var.set("testuser")
        self.app.password_var.set("Testpassword1!")
        self.app.login()
        self.assertEqual(self.app.current_username, "testuser")

    def test_login_failure(self):
        # Simulate login failure
        self.app.show_login_screen()
        self.app.username_var.set("testuser")
        self.app.password_var.set("wrongpassword")
        self.app.login()
        self.assertIsNone(self.app.current_username)

if __name__ == "__main__":
    unittest.main()
