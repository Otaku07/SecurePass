import unittest
import sqlite3
import os
import sys
sys.path.append(os.path.abspath('../Src'))
from SecurePassBy import DB_NAME,generate_salt, derive_key, encrypt_data, decrypt_data, create_database

class TestPasswordManagerFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a database for testing
        cls.db_name = DB_NAME
        if os.path.exists(cls.db_name):
            os.remove(cls.db_name)
        create_database()  # Ensure the database is set up

    def test_generate_salt(self):
        # Test salt generation
        salt = generate_salt()
        self.assertEqual(len(salt), 32)  # Assuming SALT_SIZE is 32

    def test_derive_key(self):
        # Test key derivation
        password = "testpassword"
        salt = generate_salt()
        key = derive_key(password, salt)
        self.assertEqual(len(key), 44)  # Key length should be consistent

    def test_encryption_decryption(self):
        # Test encryption and decryption
        data = "Secret Data"
        password = "testpassword"
        salt = generate_salt()
        key = derive_key(password, salt)
        encrypted_data = encrypt_data(data, key)
        decrypted_data = decrypt_data(encrypted_data, key)
        self.assertEqual(data, decrypted_data)

    def test_database_operations(self):
        # Test database operations
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Testing user existence check
        cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)", ("testuser", "hashedpassword", "salt"))
        conn.commit()

        cursor.execute("SELECT * FROM users WHERE username=?", ("testuser",))
        user = cursor.fetchone()
        self.assertIsNotNone(user)

        # Testing password storage
        cursor.execute("INSERT INTO passwords (site_name, username_site, password, salt) VALUES (?, ?, ?, ?)", ("testsite", "testuser", "testpassword", "salt"))
        conn.commit()

        cursor.execute("SELECT * FROM passwords WHERE username_site=?", ("testuser",))
        password_record = cursor.fetchone()
        self.assertIsNotNone(password_record)

        conn.close()

    @classmethod
    def tearDownClass(cls):
        # Remove the test database
        if os.path.exists(cls.db_name):
            os.remove(cls.db_name)

if __name__ == "__main__":
    unittest.main()
