def dnsPacketAnswer(requestID,answer):
    """construit une reponse DNS"""
    # TODO: La requête DNS envoyée au résolveur doit respecter le protocole DNS et contenir un champ ID différent pour chaque requête pour assurer la correspondance requête/réponse qui n'est pas donnée dans le protocole DNS classique en UDP.
    

    # construction du packet header + QNAME + QTYPE + QCLASS*
    
    #header
    ID = requestID
    #TODO: recursif ?
    FLAGS = 0x8000

    QDCOUNT = 0x0001 #One question follows
    ANCOUNT = 0x0000 #No answers follow 
    NSCOUNT = 0x0000 #No records follow
    ARCOUNT = 0x0000 #No additional records follow


    


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
    lookedForName = lookedForName.split(".")
    data = 0x0
    totalLenght = 0
    for part in lookedForName:
        #convert to bin
        binStr = [ord(c) for c in part]
        charOffset = len(part)*8
        binPart = 0
        for char in binStr:
            charOffset = charOffset - 8
            binPart =  binPart | (char<<charOffset)
        totalLenght = totalLenght + len(part)
        binPart = binPart | (len(part)<<len(part)*8)
        data = (data<<len(part)*8+4) | binPart
    #totalLenght * 2 car chaque char est codé sur 2 oct + 2oct pour la longeur de chaque partie le tout fois 8 car 1 octet = 8 bit
    dataSize = (totalLenght*2+len(lookedForName)*2)*8
    binaryPacket = (header<<dataSize) | data

    #TODO: A,MX,NS
    QTYPE = 0x0001
    #qclass
    QCLASS = 0x0001
    dataSize = 4*8
    binaryPacket = (binaryPacket<<dataSize) | QTYPE
    binaryPacket = (binaryPacket<<dataSize) | QCLASS


    n = int(bin(binaryPacket)[2:], 2)
    binaryPacket = binascii.unhexlify('%x' % n)
     # Send request message to server
    dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_send = dnsSocket.sendto(binaryPacket,(dnsAddr, DEFAULT_DNS_PORT))

    # Receive message from server
    max_bytes = 4096
    (raw_bytes2,src_addr) = dnsSocket.recvfrom(max_bytes)
    print "from:" 
    print src_addr
    print "data:"
    print(raw_bytes2) 

if __name__ == "__main__":
    #smtp.cold.net	IN  A	213.186.33.5
    dnsPacketAnswer(0x0000,['smtp.cold.net', 'IN', 'A', '213.186.33.5'])