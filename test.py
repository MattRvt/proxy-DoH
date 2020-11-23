#!/usr/bin/python
# -*-coding:Latin-1 -*

import struct
import proxy
import senddns_cpy
import base64

def sendDoh(data,s):
    """
    envoie les donnes data sur la socket s
    """
    path="?dns="+data
    mystring = """:status= 200
Content-Type: application/dns-message

%s""" % (data)
    print 'sent HTTP request'
    #s.send(mystring)
    return mystring

def test(request):
    request = base64.b64decode(request)
    (p,dommaineName,requestType,requestClass) = proxy.parseRequest(request,12)

    currentRequestID = proxy.generateID()
    request = struct.pack(">H",currentRequestID)+request[2:]


    #get list of answer to return to client
    pathToBDD = 'boxa/etc/bind/db.static'
    records = []
    domaineRecord = proxy.bddGetAnswer(dommaineName,proxy.numbertotype(requestType),pathToBDD,records)

    rawBytesAnswer = proxy.dnsPacketAnswer([p,dommaineName,requestType,requestClass],domaineRecord)

    idMatch = (currentRequestID == struct.unpack(">H",request[:2])[0])
    ################################ client side

    data=rawBytesAnswer

    print "\n"
    header=struct.unpack(">HBBHHHH",data[:12])
    qdcount=header[3]
    ancount=header[4]
    nscount=header[5]
    arcount=header[6]

    i=12

    print "QUERY: "+str(qdcount)+", ANSWER: "+str(ancount)+", AUTHORITY: "+str(nscount)+", ADDITIONAL: "+str(arcount)+'\n'
    if qdcount:
      print "QUERY SECTION :\n"
      for j in range(qdcount):
        pos,name,typ,clas=senddns_cpy.retrquest(data,i)
        i=pos
        print name+"   "+senddns_cpy.numbertotype(typ)+"   "+str(clas)
      print "\n"

    if ancount:
      print "ANSWER SECTION :\n"
      for j in range(ancount):
        pos,name,typ,clas,ttl,datalen,dat=senddns_cpy.retrrr(data,i)
        i=pos
        if typ == 15:
          print name+"   "+senddns_cpy.numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat[0])+"   "+dat[1]
        else:
          print name+"   "+senddns_cpy.numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat)
      print "\n"

    if nscount:
      print "AUTHORITY SECTION :\n"
      for j in range(nscount):
        pos,name,typ,clas,ttl,datalen,dat=senddns_cpy.retrrr(data,i)
        i=pos
        print name+"   "+senddns_cpy.numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat)
      print "\n"

    if arcount:
      print "ADDITIONAL SECTION :\n"
      for j in range(arcount):
        pos,name,typ,clas,ttl,datalen,dat=senddns_cpy.retrrr(data,i)
        i=pos
        print name+"   "+senddns_cpy.numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat)
      print "\n"


if __name__ == "__main__":
  print "\r"

  #print "./senddns.py -t A smtp.cold.net \t utilise le cache sans champ additionnel"
  #test("AAABAAABAAAAAAAABHNtdHAEY29sZANuZXQAAAEAAQ==")

  print "./senddns.py -t MX cold.net \t utilise cache avec champ additionel"
  test("AAABAAABAAAAAAAABGNvbGQDbmV0AAAPAAE=")
