#!/usr/bin/python
# -*-coding:Latin-1 -*

# imports
import socket




# functions


def convertEncoding():
    """change le codage pour revenir au codage binaire classique des requêtes DNS"""


def sendDNSRequest(name, socket):
    """envoie une requete DNS"""
    # TODO: La requête DNS envoyée au résolveur doit respecter le protocole DNS et contenir un champ ID différent pour chaque requête pour assurer la correspondance requête/réponse qui n'est pas donnée dans le protocole DNS classique en UDP.


def sendHTTPRequest(data, socket):
    """envoie une requete HTTP"""
    # TODO: La réponse HTTP doit être au format suivant :
    # "
    # HTTP/1.0 200 OK
    # Content-Type: application/dns-message
    # Content-Length: taille_de_la_réponse
    #
    # réponse_dns
    # "


def askToCache():
    """part3: si le nom est present dans le cache, renvoie l'ip associé si non renvoi 0"""
    # TODO: relir sujet avant de faire


# main
if __name__ == __main__:
    print "en attente d'une connexion.."
    ADRESSE = ''
    PORT = 80

    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.bind((ADRESSE, PORT))
    serveur.listen(1)

    # réceptionner la requête transmise par le client,
    client, adresseClient = serveur.accept()
    print 'Connexion de ', adresseClient

    donnees = client.recv(1024)
    if not donnees:
        print 'Erreur de reception.'
    else:
        print 'Reception de:\n' + donnees
        # TODO: message derreur si requete non valide => lorsque la requête HTTP n'est pas GET, ou lorsque l'url ne contient pas de variable "dns".
        """
        GET /?dns=AAABAAABAAAAAAAABGJsdWUDbmV0AAAPAAE= HTTP/1.0
        Host: 1.2.3.54
        Accept: application/dns-message
        """
        # changer le codage pour revenir au codage binaire classique des requêtes DNS

        # envoyer la requête DNS au résolveur (dont l'adresse se trouve dans le fichier "/etc/resolv.conf" de boxa).

        # Ce résolveur s'occupera de faire la séquence de requêtes itératives permettant d'obtenir la réponse

        # Une fois la réponse DNS obtenue du résolveur, le message doit être transmis au client via une réponse HTTP.
        reponse = donnees.upper()
        # print 'Envoi de :' + reponse
        n = client.send(reponse)
        if (n != len(reponse)):
            print 'Erreur envoi.'
        else:
            print 'Envoi ok.'

    print 'Fermeture de la connexion avec le client.'
    client.close()
    print 'Arret du serveur.'
    serveur.close()
