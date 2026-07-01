#!/usr/bin/python3


def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

# 1. TES DEUX CHAINES CHIFFREES EN CONSTANTES
CIPHERTEXT1_HEX = ""
CIPHERTEXT2_HEX = ""

# Conversion des chaînes hexadécimales en octets (bytes)
ciphertext1 = bytes.fromhex(CIPHERTEXT1_HEX)
ciphertext2 = bytes.fromhex(CIPHERTEXT2_HEX)

# 2. RECONSTRUCTION DU TEXTE CLAIR 1 (Avec le doublon "Agent Agent")
# C'est ce que le serveur a construit lors de ta première saisie
long_codename = b"Agent username, your clearance for Operation Blackout is:"
plaintext1 = b"Agent " + long_codename + b", your clearance for Operation Blackout is: "

# 3. EXTRACTION DU KEYSTREAM
# On XOR le premier chiffré avec le premier texte clair connu
keystream = xor_bytes(ciphertext1, plaintext1)

# 4. DECHIFFREMENT DU SECOND MESSAGE CONTAINING THE FLAG
# On applique la clé (keystream) sur le deuxième chiffré
plaintext2 = xor_bytes(ciphertext2, keystream)

# Affichage du résultat final net
print("[+] Résultat du déchiffrement local :")
print(plaintext2.decode(errors="ignore"))
