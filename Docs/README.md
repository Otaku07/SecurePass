# SecurePass Manager

SecurePass Manager est un gestionnaire de mots de passe sécurisé permettant de stocker et de gérer vos mots de passe en toute sécurité.

## Prérequis

Assurez-vous d'avoir les logiciels suivants installés :

- Visual Studio Code
- SQLite
- Bibliothèques Python : `tkinter`, `cryptography`, `bcrypt`

## Installation

Clonez le dépôt GitHub :

   ```bash
   git clone https://github.com/Otaku07/SecurePass.git
   ```

## Utilisation

Pour exécuter l'application dans Visual Studio Code, lancez simplement le script `SecurePassBy.py` en vous assurant d'être dans le repertoire d'où vous avez cloné le projet:

```bash
python SecurePassBy.py
```

## Organisation des fichiers

- **Src/** : Contient le code source du projet.
  - `SecurePassBy.py` : Script principal de l'application.
  - `SecurePassBy.db` : Base de données contenant les informations utilisateur et mots de passe.
  - `setup.py` : Script permettant de générer l'exécutable SecurePassBy.exe

- **Tests/** : Contient les tests d'intégration et unitaires du projet.
  - `TestIntégration.py`
  - `TestUnitaire.py`

Pour les executer, il faut faire la commande
```bash
python -m unittest TestIntegration.py
python -m unittest TestUnitaire.py
```

- **docs/** : Contient la documentation du projet.
  - `README.md`
  - `Description Projet SecurePass_NGO MBEDEG_M2 CYBER.pdf` : Rapport du projet.

## Création de l'exécutable

Pour créer le fichier exécutable à partir du script Python, nous avons utilisé `cx_Freeze` :

1. Créez le fichier `setup.py`(déjà dans le dossier Src) avec le contenu suivant :

   ```python
   import sys
   from cx_Freeze import setup, Executable
   import os

   build_exe_options = {
       "packages": ["sqlite3", "tkinter", "cryptography", "bcrypt"],
       "include_files": ["SecurePassBy.db"]
   }

   base = None
   if sys.platform == "win64":
       base = "Win64GUI"

   setup(
       name = "SecurePass Manager",
       version = "1.0",
       description = "SecurePass Manager Password Manager",
       options = {"build_exe": build_exe_options},
       executables = [Executable("SecurePassBy.py", base=base)]
   )
   ```

2. Exécutez la commande suivante pour créer l'exécutable :

   ```bash
   python setup.py build

   ```

## Latences et bugs

Au cas où le logiciel plante, le dossier SecurePass Test contient un fichier "exe" fonctionnel d'une version antérieur mais qui permet de parcourir toutes les étapes présentées dans le rapport final.

## Auteur

NGO MBEDEG LE-NYE ESPERANCE