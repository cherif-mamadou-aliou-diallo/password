import hashlib

def verifier_mot_de_passe(password):
    # Vérifie les exigences de sécurité du mot de passe
    return (
        len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in "!@#$%^&*" for c in password)
    )

def hash_password(password):
    # Crypte le mot de passe avec l'algorithme SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def main():
    while True:
        user_password = input("Veuillez entrer un mot de passe : ")

        if verifier_mot_de_passe(user_password):
            hashed_password = hash_password(user_password)
            print("Mot de passe valide.")
            print("Mot de passe crypté (SHA-256) :", hashed_password)
            break
        else:
            print("Erreur : Le mot de passe ne respecte pas les exigences de sécurité.")
            print("Veuillez choisir un nouveau mot de passe.")

if __name__ == "__main__":
    main()
