#!/usr/bin/python
# -*-coding:Latin-1 -* 

#### imports
import socket

#### functions
def convertEncoding():
    """change le codage pour revenir au codage binaire classique des requêtes DNS"""

def sendDNSRequest(name):
    "envoie une requete DNS"

def sendHTTPRequest(name):
    "envoie une requete DNS"

#### main
ADRESSE = ''
PORT = 6789

serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur.bind((ADRESSE, PORT))
serveur.listen(1)

#réceptionner la requête transmise par le client,
client, adresseClient = serveur.accept()
print 'Connexion de ', adresseClient

donnees = client.recv(1024)
if not donnees:
        print 'Erreur de reception.'
else:
        print 'Reception de:' + donnees
        #changer le codage pour revenir au codage binaire classique des requêtes DNS

        #envoyer la requête DNS au résolveur (dont l'adresse se trouve dans le fichier "/etc/resolv.conf" de boxa).
         
        # Ce résolveur s'occupera de faire la séquence de requêtes itératives permettant d'obtenir la réponse
        
        #Une fois la réponse DNS obtenue du résolveur, le message doit être transmis au client via une réponse HTTP.
        reponse = donnees.upper()
        print 'Envoi de :' + reponse
        n = client.send(reponse)
        if (n != len(reponse)):
            print 'Erreur envoi.'
        else:
            print 'Envoi ok.'


print 'Fermeture de la connexion avec le client.'
client.close()
print 'Arret du serveur.'
serveur.close()


