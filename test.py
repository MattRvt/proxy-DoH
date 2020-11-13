import struct
import base64

r = """:status= 200
Content-Type: application/dns-message

AACFgAABAAEAAAABBGJsdWUDbmV0AAACAAHADAACAAEAAOpgAAoHZG5zYmx1ZcAMwCYAAQABAADqYAAEAQIDBA==""" % ()
pos=0
l=r.splitlines()
if l[0].split(' ')[1] <> "200":
    print "Erreur : code "+ l[0].split(' ')[1]
    exit(1)
pos=len(l[0])+1
i=1
while l[i].split(': ')[0]<> 'Content-Type':
    pos=pos+len(l[i])+1
    i=i+1
if l[i].split(': ')[1] <> 'application/dns-message':
    print "Erreur : mauvais type "+ l[i].split(' ')[1]
    exit(1)
while l[i]<>'':
    pos=pos+len(l[i])+1
    i=i+1

################## traitement
data = r[pos+1:]
data = base64.b64decode(data)
header=struct.unpack(">HBBHHHH",data[:12])
qdcount=header[3]
ancount=header[4]
nscount=header[5]
arcount=header[6]

i=12

print "QUERY: "+str(qdcount)+", ANSWER: "+str(ancount)+", AUTHORITY: "+str(nscount)+", ADDITIONAL: "+str(arcount)+'\n'




