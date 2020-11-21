#!/usr/bin/python
# -*-coding:Latin-1 -*

"""
pour ecouter entre proxy et dns
vdump "colla" | wireshark -i - -k &

pour ecouter entre proxy et alice
vdump "lana" | wireshark -i - -k &


./senddns.py -t NS blue.net


to test with cache non recursif
./senddns.py -t A smtp.cold.net

https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
"""


########## imports
import socket
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
import base64
import binascii
import struct
import random

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
def bddGetAnswer(dommaineName,requestType,pathToBDD,recordsAnswer):
    """
    consulte une base de données d'enregistrements DNS placée dans le fichier "boxa/etc/bind/db/static"
    return un tablea de la forme tabl = ["cold.net","MX","5","smtp.cold.net"]
    """

    resolvconf = open(pathToBDD, "r")
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
    if (requestType.upper() == "MX") and (len(records)>1):
        records = [max(records,key=lambda record: record[3])]

    #si tout va bien, il ne rest qu'un seul resultat
    if len(records)>1:
        print "ERROR: plus d'un resultat trouvé."
        print records
    elif len(records)==0:
        return 
    else:
      if recordIsFinal(records):
        recordsAnswer.append(records[0])
        return recordsAnswer
      else:
        recordsAnswer.append(records[0])
        #TODO: champs additionnel type A ?
        return bddGetAnswer(records[0][-1],"A",pathToBDD,recordsAnswer)


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
    serveur = socket
    serveur.listen(1)

    client, adresseClient = serveur.accept()
    print 'Connexion de ', adresseClient
    donnees = client.recv(1024)
    return donnees,client

def generateID():
    #le module secrets serait preferable mais il n'est pas disponible pour python 2.5
    generatedId = random.randint(1,65535)
    return generatedId

def recordIsFinal(record):
  return (len(record[0][-1].split('.'))==4 and int(record[0][-1].split('.')[0]))

def dnsPacketAnswer(request,records):
    """construction de la requete demandant les enregistrements de type typ pour le nom de domaine name"""
    data=""
    #id sur 2 octet
    data=data+struct.pack(">H",0x0000)
    # octet suivant : flag
    data=data+struct.pack(">H",0x8580)
    #QDCOUNT sur 2 octets
    data=data+struct.pack(">H",1) #One question follows
    data=data+struct.pack(">H",len(records)) #TODO: 0 answer follows
    data=data+struct.pack(">H",0) #Autority RRs
    data=data+struct.pack(">H",0) #Additional RRs

    ############# Queries

    splitname=request[1].split('.')
    for c in splitname:
      data=data+struct.pack("B",len(c))
      for l in c:
        data=data+struct.pack("c",l)
    data=data+struct.pack("B",0)
    #TYPE
    data=data+struct.pack(">H",request[2])
    #CLASS 1 (IN) par defaut
    data=data+struct.pack(">H",1)

    ######## ANSWER

    #name is pointer 
    #data=data+struct.pack(">H",0xc)
    #pointer is to the name of offset 12
    #data=data+struct.pack(">H",0x00c)


    for answer in records:
      splitname=answer[0].split('.')
      for c in splitname:
        data=data+struct.pack("B",len(c))
        for l in c:
          data=data+struct.pack("c",l)
      data=data+struct.pack("B",0)


      #answer type
      data=data+struct.pack(">H",typenumber(answer[2]))

      #answer class
      #CLASS 1 (IN) par defaut
      data=data+struct.pack(">H",1)

      #reponse validity 
      data=data+struct.pack(">HH",0x001,0x0248)

      if (recordIsFinal([answer])):
        


        #addr length
        data=data+struct.pack(">H",0x0004)

        #addresse
        addr = answer[-1].split('.')
        data=data+struct.pack("B",int(addr[0]))
        data=data+struct.pack("B",int(addr[1]))
        data=data+struct.pack("B",int(addr[2]))
        data=data+struct.pack("B",int(addr[3]))
      else:
        #data length
        #TODO: calc data len
        splitAnsw = answer[-1].split('.')
        dataLen = len(splitAnsw)+3
        for part in splitAnsw:
          dataLen = dataLen + len(part)
  
        data=data+struct.pack(">H",dataLen)

        if (answer[2] == 'MX'):
          data=data+struct.pack(">H",int(answer[3]))

        splitname=answer[-1].split('.')
        for c in splitname:
          data=data+struct.pack("B",len(c))
          for l in c:
            data=data+struct.pack("c",l)
        data=data+struct.pack("B",0)

    #TODO: peux prioritaire, compression nom de domaine, relir sujet
    return data

    
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

def typenumber(typ):
  """associe un entier a un nom de type"""
  if typ=='A':
    return 1
  if typ=='MX':
    return 15
  if typ=='NS':
    return 2

def numbertotype(typ):
  """associe son type a un entier"""
  if typ==1:
    return 'A'
  if typ==15:
    return 'MX'
  if typ==2:
    return 'NS'

def tupletostring(t):
  """concatene un tuple de chaines de caracteres en une seule chaine"""
  s=""
  for c in t:
    s=s+c
  return s

def listtostring(l):
  """concatene une liste de chaines de caracteres en une seule chaine"""
  s=""
  for c in l:
    s=s+c
  return s

def getname(string,pos):
  """recupere le nom de domaine encode dans une reponse DNS a la position p, en lecture directe ou en compression"""
  p=pos
  save=0
  name=""
  l=1
  if l==0:
    return p+1,""
  while l:
    l=struct.unpack("B",string[p])[0]
    if l>=192:
      #compression du message : les 2 premiers octets sont les 2 bits 11 puis le decalage depuis le debut de l'ID sur 14 bits
      if save == 0:
        save=p
      p=(l-192)*256+(struct.unpack("B",string[p+1])[0])
      l=struct.unpack("B",string[p])[0]
    if len(name) and l:
      name=name+'.'
    p=p+1
    name=name+tupletostring(struct.unpack("c"*l,string[p:(p+l)]))
    p=p+l
  if save > 0:
    p=save+2
  return p,name

def parseRequest(string,pos):
  """decrit une section question presente dans la reponse DNS string a la position pos"""
  p=pos
  p,name=getname(string,p)
  typ = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  clas = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  return p,name,typ,clas




########## main
if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ADRESSE = ''
    PORT = 80
    server.bind((ADRESSE, PORT))
    while 1:
        # réceptionner la requête transmise par le client
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
            print(requestFromClient.path)                 #/?dns=AAABAAABAAAAAAAABmRvbWFpbgRuYW1lAAAPAAE=
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

            (p,dommaineName,requestType,requestClass) = parseRequest(request,12)
            pathToBDD = '../etc/bind/db.static'
            records = []
            domaineRecord = bddGetAnswer(dommaineName,numbertotype(requestType),pathToBDD,records)

            if domaineRecord and (len(domaineRecord) > 0):
                print "réponse trouvé en cache !"
                answer = domaineRecord
                rawBytesAnswer = dnsPacketAnswer([p,dommaineName,requestType,requestClass],domaineRecord)

                #la requete est traiter en internet, la reponse correspond forcement
                idMatch = 1
            else:
                print "Pas de réponse en cache, demande au DNS.."
                # envoyer la requête DNS au résolveur (dont l'adresse se trouve dans le fichier "/etc/resolv.conf" de boxa).
                dnsAddr,port=findaddrserver()
                dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                #change l'ID de la requete
                currentRequestID = generateID()
                request = struct.pack(">H",currentRequestID)+request[2:]

                #envoie de la requete
                bytes_send = dnsSocket.sendto(request,(dnsAddr, DEFAULT_DNS_PORT))

                # Ce résolveur s'occupera de faire la séquence de requêtes itératives permettant d'obtenir la réponse

                # Une fois la réponse DNS obtenue du résolveur, le message doit être transmis au client via une réponse HTTP.
                max_bytes = 4096
                #TODO: pas de reponse du dns
                #TODO: le DNS ne trouve pas la rep a la querry
                print "attente d'une reponse du serveur DNS.."
                
                (rawBytesAnswer,src_addr) = dnsSocket.recvfrom(max_bytes)
                
                #test si l'id correspond
                idMatch = (currentRequestID == struct.unpack(">H",request[:2])[0])
            
            if idMatch:
              print "envoie d'une reponse au client.."
              sendDoh(rawBytesAnswer,client)
              print 'Fermeture de la connexion avec le client.'
              client.close()
            else:
              print "ERROR: le serveur DNS n'a pas répondu avec le bon ID."
              client.close()
    print 'Arret du serveur.'
    server.close()
    dnsSocket.close()