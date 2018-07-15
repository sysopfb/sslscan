import socket
import threading

def TCP_connect(ip, port, delay, key, output):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.settimeout(delay)
	try:
		sock.connect((ip,port))
		output[key] = 'up'
	except:
		pass
	sock.close()

#Expects list of Name,ip:port
def scan_ips(data):
	delay=5
	threads = []
	output = {}

	for rec in data.split('\n'):
		if rec == '' or rec[0] == '#':
			continue

		temp = rec
		[ip,port] = temp.split(':')
		
		t = threading.Thread(target=TCP_connect, args=(ip,int(port), delay, rec, output))
		threads.append(t)

	for i in range(len(threads)/100):
		num_threads_left = len(threads)-i*100
		num_threads = 100
		if num_threads_left < 100:
			num_threads = num_threads_left

		for j in range(i*100,i*100+num_threads):
			threads[j].start()
		for j in range(i*100,i*100+num_threads):
			threads[j].join()

#	for i in range(len(threads)):
#		threads[i].start()

#	for i in range(len(threads)):
#		threads[i].join()

	return('\n'.join(output.keys()))



