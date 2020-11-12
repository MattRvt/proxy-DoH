#!/usr/bin/python
# -*-coding:Latin-1 -*

########## imports
import socket
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
import base64

########## constant
PARAMETER_NAME = 'dns'
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
def waitForConnection():
    """attend une connexion et return les donnes recu"""
    print "en attente d'une connexion.."
    ADRESSE = ''
    PORT = 80

    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.bind((ADRESSE, PORT))
    serveur.listen(1)

    client, adresseClient = serveur.accept()
    print 'Connexion de ', adresseClient
    donnees = client.recv(1024)
    return donnes

def convertEncoding(encodedValue):
    """change le codage pour revenir au codage binaire classique des requêtes DNS"""
    #TODO: CF sujet le truc des 2 derniers caracters
    decodedValue = base64.b64decode(encodedValue)
    return decodedValue

def stringToHex(string):
    #TODO: convert string to it's hexa notation
    return hex(string)

def generateID():
    #TODO: generate a unique ID
    return 0xdb42

def sendDNSRequest(DNSipAddress,lookedForName,requestType):
    """envoie une requete DNS"""
    # TODO: La requête DNS envoyée au résolveur doit respecter le protocole DNS et contenir un champ ID différent pour chaque requête pour assurer la correspondance requête/réponse qui n'est pas donnée dans le protocole DNS classique en UDP.
    
    lookedForName = lookedForName.split(".")

    # construction du packet header + QNAME + QTYPE + QCLASS*
    
    #header
    ID = generateID()
    FLAGS = 0x0100

    QDCOUNT = 0x0001 #One question follows
    ANCOUNT = 0x0000 #No answers follow 
    NSCOUNT = 0x0000 #No records follow
    ARCOUNT = 0x0000 #No additional records follow



    #TODO: qname part
    #data = ''
    #for part in lookedForName:
    #    data + stringToHex(len(part))
    #    data + stringToHex(part)
    data = 0x00
    #qtype
    #TODO: A,MX,NS
    QTYPE = 0x0001
    #qclass
    QCLASS = 0x0001


    IDOffset = 80
    flagsOffset = IDOffset - 16
    qdCountOffset = flagsOffset - 16
    anCountOffset = qdCountOffset -16
    nscountOffset = anCountOffset - 16
    arCountOffset = nscountOffset - 16
    header = (ID<<IDOffset) 
    header = header | (FLAGS<<flagsOffset) 
    header = header | (QDCOUNT<<qdCountOffset) 
    header = header | (ANCOUNT<<anCountOffset) 
    header = header | (NSCOUNT<<nscountOffset) 
    header = header | (ARCOUNT<<arCountOffset)


    #TODO: format data
    #TODO binaryPacket =



    print bin(header)

     # Send request message to server
     # print(raw_bytes)
    bytes_send = s.sendto(raw_bytes,server_address)

    # Receive message from server
    max_bytes = 4096
    (raw_bytes2,src_addr) = s.recvfrom(max_bytes)

    print(raw_bytes2)    
    
    


def sendHTTPRequest(data, client):
    """envoie une requete HTTP"""
    # TODO: La réponse HTTP doit être au format suivant :
    # "
    # HTTP/1.0 200 OK
    # Content-Type: application/dns-message
    # Content-Length: taille_de_la_réponse
    #
    # réponse_dns
    # "

    print 'Envoi de :' + reponse
    n = client.send(reponse)
    if (n != len(reponse)):
        print 'Erreur envoi.'
    else:
        print 'Envoi ok.'

def getDNSaddr(resolvCondPath):
  """recupere l'adresse de couche transport du serveur DNS DoH depuis le fichier /etc/resolv.conf"""
  resolvconf = open(resolvCondPath, "r")
  lines = resolvconf.readlines()
  i=0
  while lines[i].split()[0]<>'nameserver':
    i=i+1
  server = lines[i].split()[1]
  resolvconf.close()
  return (server,80)


def askToCache():
    """part3: si le nom est present dans le cache, renvoie l'ip associé si non renvoi 0"""
    # TODO: relir sujet avant de faire



########## main
if __name__ == "__main__":
    # réceptionner la requête transmise par le client,
    #TODO: donnees = waitForConnection()
    
    donnees = (
        'GET /?dns=AAABAAABAAAAAAAABGJsdWUDbmV0AAAPAAE= HTTP/1.0\r\n'
        'Host: 1.2.3.54\r\n'
        'Accept: application/dns-message\r\n'
    )
    

    if not donnees:
        print 'Erreur de reception.'
    else:
        print 'Reception de:\n'
        requestFromClient = HTTPRequest(donnees)
        print(requestFromClient.error_code)          #None
        print(requestFromClient.command)             #GET
        print(requestFromClient.path)                #/?dns=AAABAAABAAAAAAAABmRvbWFpbgRuYW1lAAAPAAE=
        print(requestFromClient.request_version)     #HTTP/1.0
        print(len(requestFromClient.headers))        #2
        print(requestFromClient.headers.keys())      #['host', 'accept']
        print(requestFromClient.headers['host'])     #1.2.3.54



        # TODO: message derreur si requete non valide => lorsque la requête HTTP n'est pas GET, ou lorsque l'url ne contient pas de variable "dns".
        if (requestFromClient.command != "GET"):
            print 'ERROR: Method must be GET'
            exit(1)

        #TODO: gere le cas de DNS ecrit en majuscule dans la requete
        url = requestFromClient.path
        
        #TODO: querry string pars ne fonctionnement pas dans le lab
        #parsed = urlparse(url)
        #params = parse_qs(parsed.query)



        #if (PARAMETER_NAME not in params):
        #    print 'ERROR: DNS value not found'
        #    exit(1)
        
        # change le codage pour revenir au codage binaire classique des requêtes DNS
        #TODO: gere le type de requete (mx,...)
        #domainName = convertEncoding(params[PARAMETER_NAME][0])
        domainName = convertEncoding('AAABAAABAAAAAAAABGJsdWUDbmV0AAAPAAE=')
        # envoyer la requête DNS au résolveur (dont l'adresse se trouve dans le fichier "/etc/resolv.conf" de boxa).
        #TODO: dnsAddr = getDNSaddr("/etc/resolv.conf") #TODO: verifier si .net manquant
        dnsAddr = "1.2.3.4"
        requestType = "MX"
        # Create UDP socket
        dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #dnsSocket.connect((dnsAddr, DEFAULT_DNS_PORT))
        sendDNSRequest(dnsSocket,domainName,requestType)

        # Ce résolveur s'occupera de faire la séquence de requêtes itératives permettant d'obtenir la réponse

        # Une fois la réponse DNS obtenue du résolveur, le message doit être transmis au client via une réponse HTTP.
        #TODO: sendHTTP(data)

    print 'Fermeture de la connexion avec le client.'
    client.close()
    print 'Arret du serveur.'
    serveur.close()
    dnsSocket.close()
