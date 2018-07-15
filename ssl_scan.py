import socket
import io
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys
import ssl
import hashlib
import base64
import sqlite3
import sock_scanner
import datetime
import struct
import binascii

date = datetime.datetime.now().strftime("%Y%m%d")

def get_cert_pem(domain,port):
	s = socket.socket()
	s.settimeout(5)
	c = ssl.wrap_socket(s)
	try:
		c.connect((domain,port))
		cert = c.getpeercert(True)
		pem = "-----BEGIN CERTIFICATE-----\n"+base64.b64encode(cert)+"\n-----END CERTIFICATE-----"
	except:
		#open('log.txt', 'a').write("Failure for: "+str(domain)+':'+str(port)+'\n')
		cert = 0
		pem = 0
	return (cert,pem)

def hashdata(data):
	md5 = hashlib.md5(data).hexdigest()
	sha1 = hashlib.sha1(data).hexdigest()
	sha256 = hashlib.sha256(data).hexdigest()
	return(md5,sha1,sha256)

#CREATE TABLE certs (id INTEGER PRIMARY KEY, ip text, port text, md5 text, sha1 text, sha256 text, cert blob, certpp text, recdate text);
def insert_cert(conn, ip, port, der, cert):
	(md5,sha1,sha256) = hashdata(der)
	print(sha1)
	c = conn.cursor()
	c.execute('select * from certs where sha256=? and ip=?',(sha256,ip,))
	certrec = c.fetchone()
	if certrec == None:
		x509obj = x509.load_pem_x509_certificate(cert, default_backend())
		cert_str = str(x509obj.subject)
		substrate = pem.readPemFromFile(io.BytesIO(cert))
		certobj = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
		cert_str += certobj.prettyPrint()
		sql = '''insert into certs
			values (NULL, ?, ?, ?, ?, ?, ?, ?,?);'''
		c.execute(sql,[ip,port,md5,sha1,sha256,sqlite3.Binary(cert),cert_str,date])
		certid = c.lastrowid
		conn.commit()
	else:
		certid = certrec[0]
	return certid

def search_cert(conn, search_s, all_flag):
	c = conn.cursor()
	if not all_flag:
		c.execute("select ip,port,certpp,recdate from certs where certpp like ? and recdate=?",(search_s, date))
	else:
		c.execute("select ip,port,certpp,recdate from certs where certpp like ?",(search_s,))
	out = c.fetchall()
	if out == []:
		#Need to write a better x509 asn1 parser...
		if not all_flag:
			c.execute("select ip,port,certpp,recdate from certs where certpp like ? and recdate=?",(binascii.hexlify(search_s), date))
		else:
			c.execute("select ip,port,certpp,recdate from certs where certpp like ?",(binascii.hexlify(search_s), ))
		out = c.fetchall()
	return out

def cidr_to_list(r):
	(ip, cidr) = r.split('/')
	cidr = int(cidr) 
	host_bits = 32 - cidr
	i = struct.unpack('>I', socket.inet_aton(ip))[0] # note the endianness
	start = (i >> host_bits) << host_bits # clear the host bits
	end = start | ((1 << host_bits) - 1) 
	out = []
	for i in range(start, end):
		out.append(socket.inet_ntoa(struct.pack('>I',i)))
	return out


def main():
	conn = sqlite3.connect('cert.db')

	temp = ""
	if len(sys.argv) < 3:
		print("Params: \nscan <cidr> <port>\nsearch <search string>\n")
		sys.exit(-1)
	
	if sys.argv[1] == 'scan':
		temp = ""
		port = sys.argv[3]
		ips = cidr_to_list(sys.argv[2])
		for ip in ips:
			temp += ip+':'+port+'\n'
		out = sock_scanner.scan_ips(temp)
		for line in out.split('\n'):
			(host,port) = line.split(':')

			(der,pem) = get_cert_pem(host,int(port))
			if pem != 0:
				print("host")
				insert_cert(conn, host, port, der,pem)
	elif sys.argv[1] == 'search':
		if sys.argv[2] == 'all':
			all_flag = True
			print(search_cert(conn, sys.argv[3],all_flag))
		else:
			all_flag = False
			print(search_cert(conn, sys.argv[2],all_flag))
		
	conn.close()

if __name__ == "__main__":
	main()
