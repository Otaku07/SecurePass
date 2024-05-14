from cx_Freeze import setup, Executable

# Define application options
options = {
    'build_exe': {
        'include_files': ['SecurePassBy.db']
    }
}

setup(
    name="SecurePassBy",
    version="0.1",
    description="My SecurePassBy application",
    options=options,
    executables=[Executable("SecurePassBy.py")],
)