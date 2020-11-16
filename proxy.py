#!/usr/bin/python
# -*-coding:Latin-1 -*

"""
pour ecouter entre proxy et dns
vdump "colla" | wireshark -i - -k &

pour ecouter entre proxy et alice
vdump "lana" | wireshark -i - -k &


./senddns.py -t NS blue.net
"""


########## imports
import socket
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
import base64
import binascii

########## constant
DEFAULT_DNS_PORT = 53

########## class
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

########## functions
def bddGetAnswer(dommaineName,requestType):
    """
    consulte une base de données d'enregistrements DNS placée dans le fichier "boxa/etc/bind/db/static"
    return un tablea de la forme tabl = ["cold.net","MX","5","smtp.cold.net"]
    """

    #TODO: change path
    resolvconf = open("boxa/etc/bind/db.static", "r")
    lines = resolvconf.readlines()
    records = []
    for line in lines:
        record = line.split()
        records.append(record)

    #remove the record with mismatch domain name
    records = filter(lambda record: record[0]==dommaineName, records)

    #remove the record with mismatch type
    records = filter(lambda record: record[2]==requestType, records)

    #select the max priority for mx type
    if (requestType.upper() == "MX"):
        records = [max(records,key=lambda record: record[3])]

    #si tout va bien, il ne rest qu'un seul resultat
    if len(records)>1:
        print "ERROR: plus d'un resultat trouvé."
        print records
    else:
        return records[0]  


def findaddrserver():
  """recupere l'adresse de couche transport du proxy DoH depuis le fichier /etc/resolv.conf"""
  resolvconf = open("/etc/resolv.conf", "r")
  lines = resolvconf.readlines()
  i=0
  while lines[i].split()[0]<>'nameserver':
    i=i+1
  server = lines[i].split()[1]
  resolvconf.close()
  return (server,80)

def sendDoh(data,s):
    """
    envoie les donnes data sur la socket s
    """
    path="?dns="+data
    mystring = """:status= 200
Content-Type: application/dns-message

%s""" % (data)
    print 'sent HTTP request'
    s.send(mystring)


def waitForConnection(socket):
    """attend une connexion et return les donnes recu"""
    print "en attente d'une connexion.."
    ADRESSE = ''
    PORT = 80

    serveur = socket
    serveur.bind((ADRESSE, PORT))
    serveur.listen(1)

    client, adresseClient = serveur.accept()
    print 'Connexion de ', adresseClient
    donnees = client.recv(1024)
    return donnees,client

def stringToHex(string):
    #TODO: convert string to it's hexa notation
    return hex(string)

def generateID():
    #TODO: generate a unique ID
    return 0xdb42

  
    
def bin(x):
    """
    bin(number) -> string

    Stringifies an int or long in base 2.
    """
    if x < 0: 
        return '-' + bin(-x)
    out = []
    if x == 0: 
        out.append('0')
    while x > 0:
        out.append('01'[x & 1])
        x >>= 1
        pass
    try: 
        return '0b' + ''.join(reversed(out))
    except NameError, ne2: 
        out.reverse()
    return '0b' + ''.join(out)



def askToCache():
    """part3: si le nom est present dans le cache, renvoie l'ip associé si non renvoi 0"""
    # TODO: relir sujet avant de faire



########## main
if __name__ == "__main__":
    # réceptionner la requête transmise par le client
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    (donnees,client) = waitForConnection(server)
    
    #donnees = (
    #    'GET /?dns=AAABAAABAAAAAAAABGJsdWUDbmV0AAAPAAE= HTTP/1.0\r\n'
    #    'Host: 1.2.3.54\r\n'
    #    'Accept: application/dns-message\r\n'
    #)
    

    if not donnees:
        print 'Erreur de reception.'
    else:
        requestFromClient = HTTPRequest(donnees)

        #print(requestFromClient.error_code)          #None
        #print(requestFromClient.command)             #GET
        #print(requestFromClient.path)                #/?dns=AAABAAABAAAAAAAABmRvbWFpbgRuYW1lAAAPAAE=
        #print(requestFromClient.request_version)     #HTTP/1.0
        #print(len(requestFromClient.headers))        #2
        #print(requestFromClient.headers.keys())      #['host', 'accept']
        #print(requestFromClient.headers['host'])     #1.2.3.54



        # message derreur si requete non valide => lorsque la requête HTTP n'est pas GET, ou lorsque l'url ne contient pas de variable "dns".
        if (requestFromClient.command != "GET"):
            print 'ERROR: Method must be GET'
            exit(1)

        # gere le cas de DNS ecrit en majuscule dans la requete
        url = requestFromClient.path
        if "DNS".upper() not in url.upper():
            print 'ERROR: Must contains parm DNS'
            exit(1)

        params = url.split('dns=')
        
        # change le codage pour revenir au codage binaire classique des requêtes DNS
        request = base64.b64decode(params[1])

        #-Lorsqu'une requête DoH arrive et que la base de donnée contient la réponse, le proxy construit lui même la réponse et l'envoie au client. Sinon, le fonctionnement du proxy est inchangé.
        print "recherche d'une reponse dans le cache.."
        #TODO: changer path domaineAddr = bddGetAnswer(dommaineName)
        domaineAddr = (1==2)
        if (domaineAddr):
            print "réponse trouvé en cache !"
            rawBytesAnswer = dnsPacket(domaineAddr)
        else:
            print "Pas de réponse en cache, demande au DNS.."
            # envoyer la requête DNS au résolveur (dont l'adresse se trouve dans le fichier "/etc/resolv.conf" de boxa).
            dnsAddr,port=findaddrserver()
            dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes_send = dnsSocket.sendto(request,(dnsAddr, DEFAULT_DNS_PORT))

            # Ce résolveur s'occupera de faire la séquence de requêtes itératives permettant d'obtenir la réponse

            # Une fois la réponse DNS obtenue du résolveur, le message doit être transmis au client via une réponse HTTP.
            max_bytes = 4096
            #TODO: pas de reponse du dns
            print "attente d'une reponse du serveur DNS.."
            (raw_bytes2,src_addr) = dnsSocket.recvfrom(max_bytes)
        print "envoie d'une reponse au client.."
        sendDoh(raw_bytes2,client)

    print 'Fermeture de la connexion avec le client.'
    client.close()
    print 'Arret du serveur.'
    server.close()
    dnsSocket.close()
