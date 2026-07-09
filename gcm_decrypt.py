#!/usr/bin/env python3
import base64
import hashlib
from Cryptodome.Cipher import AES

# Votre chaîne brute issue de confCons.xml
secret_b64 = "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="

# Décodage Base64
data = base64.b64decode(secret_b64)

# Structure GCM de mRemoteNG : 
# [0:16] Salt | [16:32] Nonce/IV | [32:-16] Ciphertext | [-16:] Auth Tag
salt = data[:16]
nonce = data[16:32]
ciphertext = data[32:-16]
tag = data[-16:]

# Dérivation PBKDF2 (Valeurs par défaut mRemoteNG : SHA1, 1000 itérations, clé de 32 octets)
password = b"mR3m"
key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)

# Déchiffrement AES-GCM
cipher = AES.new(key, AES.MODE_GCM, nonce)
cipher.update(salt) # Le sel est inclus dans les données associées (AAD)

try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    print(f"[+] Mot de passe Administrateur en clair : {plaintext}")
except ValueError as e:
    print("[-] Erreur : Échec de la vérification de l'intégrité (Tag MAC invalide).")
