#!/usr/bin/python
# -*-coding:Latin-1 -*
import binascii

def dnsPacketAnswer(requestID,answer):
    """construit une reponse DNS"""
    # TODO: La requête DNS envoyée au résolveur doit respecter le protocole DNS et contenir un champ ID différent pour chaque requête pour assurer la correspondance requête/réponse qui n'est pas donnée dans le protocole DNS classique en UDP.
    

    # construction du packet header + QNAME + QTYPE + QCLASS*
    
    #header
    ID = requestID
    #TODO: recursif ?
    FLAGS = 0x8180
    QDCOUNT = 0x0001 #One question follows
    ANCOUNT = 0x0001 #No answers follow 
    NSCOUNT = 0x0001 #1 records follow
    ARCOUNT = 0x0000 #No additional records follow


    


    IDOffset = 80
    flagsOffset = IDOffset - 16
    qdCountOffset = flagsOffset - 16
    anCountOffset = qdCountOffset -16
    nscountOffset = anCountOffset - 16
    arCountOffset = nscountOffset - 16
    header = 0x0
    header = header | (ID<<IDOffset) 
    header = header | (FLAGS<<flagsOffset) 
    header = header | (QDCOUNT<<qdCountOffset) 
    header = header | (ANCOUNT<<anCountOffset) 
    header = header | (NSCOUNT<<nscountOffset) 
    header = header | (ARCOUNT<<arCountOffset)


    name = answer[0].split(".")
    data = 0x0
    totalLenght = 0
    for part in name:
        #convert to bin
        binStr = [ord(c) for c in part]
        charOffset = len(part)*8
        binPart = 0
        for char in binStr:
            charOffset = charOffset - 8
            binPart =  binPart | (char<<charOffset)
        totalLenght = totalLenght + len(part)
        #add the lenght of the part
        binPart = binPart | (len(part)<<len(part)*8)
        #add the part to the data
        data = (data<<((len(part))*8+8)) | binPart
    #totalLenght * 2 car chaque char est codé sur 2 oct + 2oct pour la longeur de chaque partie le tout fois 8 car 1 octet = 8 bit
    dataSize = (totalLenght*2+len(name)*2)*8
    binaryPacket = (header<<dataSize) | data
    
    if (answer[2] == "A"):
        RRTYPE = 0x0001
    elif (answer[2] == "MX"):
        #TODO
        RRTYPE = 0x0001
    elif (answer[2] == "NS"):
        #TODO
        RRTYPE = 0x0001
    RRCLASS = 0x0001
    dataSize = 4*8
    binaryPacket = (binaryPacket<<dataSize) | RRTYPE
    binaryPacket = (binaryPacket<<dataSize) | RRCLASS


    n = int(bin(binaryPacket)[2:], 2)
    binaryPacket = binascii.unhexlify('%x' % n)
    #TODO: if ID start with 0, nothing is sent
    print binaryPacket

if __name__ == "__main__":
    #smtp.cold.net	IN  A	213.186.33.5
    dnsPacketAnswer(0x1000,['dnscold.cold.net', 'IN', 'A', '213.186.33.5'])