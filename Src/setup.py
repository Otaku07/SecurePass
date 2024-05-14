import os
import sys
from cx_Freeze import setup, Executable

# Dépendances supplémentaires
build_exe_options = {
    "packages": ["sqlite3", "tkinter", "cryptography", "bcrypt"],
    "include_files": [os.path.join(os.path.dirname(__file__), "SecurePassBy.db")]
}

base = None
if sys.platform == "win64":
    base = "Win64GUI"

    setup(
        name = "SecurePassBy",
        version = "1.0",
        description = "SecurePassBy Password Manager",
        options = {"build_exe": build_exe_options},
        executables = [Executable("SecurePassBy.py", base=base)]
    )
