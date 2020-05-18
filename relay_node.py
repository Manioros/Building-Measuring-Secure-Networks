import socket
import sys
import threading
import subprocess
import urllib
import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from Crypto.Cipher import AES

#tmp_hops = -1
#tmp_rtt = -1
RECV_BUFFER_SIZE = 2048


def Ping_check(name,times):
    global tmp_rtt
    rtts = subprocess.Popen(["ping" , "-c" , str(times) , name], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    #hops
    for line in iter(rtts.stdout.readline, ''):
        lastln=line
        #print(line)
    tmp_rtt = get_avg_ping(lastln)
    print("\nRELAY avg rtt : %f\n" %float(tmp_rtt))
    #print(tmp_rtt)

def get_avg_ping(value):
    flag = 0
    position = 0
    slash = 0
    for letter in value:
        if (letter == "="):
            flag = 1
        if (flag == 1) and (letter == "/"):
            slash = slash+1
            if (slash==1):
                start = position
            if (slash==2):
                end = position
        position = position + 1
    if (flag == 1):
        return value[start+1:end]
    else:#prepei na to ftiaxoume kai alloy(otan den epistrefei kati h ping)
        return -1


def Hops_check(name):
    global tmp_hops
    hops = subprocess.Popen(["traceroute" , name], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    count = 0
    for i in iter(hops.stdout.readline, ''):
        #print(i)
        count = count + 1
    count = count - 1
    tmp_hops = count
    print("\nRELAY Hops : %d\n"%int(tmp_hops))

#make private key and public key
random_number = Random.new().read
private_key = RSA.generate(2048, random_number)
public_key = private_key.publickey()
#make symmetric
random_string = os.urandom(16)
#symmetric_key = base64.b64encode(random_string)
Cipher = AES.new(random_string)


def msg_public_signature():
    #public = public_key.exportKey('PEM').decode('ascii')
    public = public_key.exportKey('PEM')
    hash_result = SHA256.new(public).digest()
    signature = private_key.sign(hash_result,'')
    #print "Public test    %s" %public
    return "msg_public_key$$" + public + "$$" + str(signature)

def encryption (message):
    global cipher
    #if (len(message) % 16 != 0):
    message +=  (16 - len(message) % 16)*'@' #+ message

    return base64.b64encode( cipher.encrypt(message) ) 
    

def decryption (message):
    global cipher
    message1 = base64.b64decode(message)
    decoded_message = cipher.decrypt(message1).decode('utf-8')
    #decoded_message = cipher.decrypt(encrypted_msg)
    padding = decoded_message.count('@')
    #return decoded_message[padding:]
    return decoded_message[:len(decoded_message)-padding]


socket_client_relay = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('', int(sys.argv[1]))
print >>sys.stderr, '\n\n\nstarting up on %s port %s \n\n\n' % server_address
socket_client_relay.bind(server_address)
socket_client_relay.listen(1)

while True:
    # Wait for a connection
    print >>sys.stderr, 'waiting for a connection'
    connection, client_address = socket_client_relay.accept()

    try:
        #print >>sys.stderr, 'connection from', client_address
        data = connection.recv(RECV_BUFFER_SIZE)
        #data = decryption(data)
        
        if (data[:10] == "msg_public"):
            #print("@@@@@@@@^^^^DATA^^^^@@@@@@%s" %data[4:])
            trash,client_pkey,client_signature = data.split("$$")
            client_public_key = RSA.importKey(client_pkey)
            hash_result = SHA256.new(client_pkey).digest()
            
            if (client_public_key.verify(hash_result,eval(client_signature))):
                print "relay received correctly client's public key "
                #print client_public_key
                message = msg_public_signature();
                #print("message to send with public key and signature %s\n" %message)
                connection.send(message)

                data = connection.recv(RECV_BUFFER_SIZE)
                symmetric_key_encrypted,client_signature = data.split("$$")
                symmetric_key_decrypted = private_key.decrypt(eval(symmetric_key_encrypted))
                
                hash_result = SHA256.new(symmetric_key_decrypted).digest()
                if (client_public_key.verify(hash_result,eval(client_signature))):
                    print("relay received correctly symmetric key")
                    symmetric_key = base64.b64decode(symmetric_key_decrypted)
                    cipher = AES.new(symmetric_key)
                else:
                    print ("relay failed to receive correctly the symmetric key")
            else:
                print "relay failed to receive correctly the public key "
        else:
            data = decryption(data)

            if (data[:9] == "dwnld_url"):
                print >>sys.stderr, 'received message "%s" ' %data
                start_msg,url = data.split(" ")
                print("Download url: %s\n" %url)
                filename = "imageR" + data[-4:]
                urllib.urlretrieve (url, filename)
                file_name_read = open(filename, 'rb')
                tmp_buffer = file_name_read.read(RECV_BUFFER_SIZE)
                
                while(tmp_buffer):
                    #message = encryption(tmp_buffer)
                    connection.send(tmp_buffer)
                    #connection.send(message)
                    tmp_buffer = file_name_read.read(RECV_BUFFER_SIZE)
                file_name_read.close()
                
                """ remove file from relay area """
                if os.path.exists(filename):
                    os.remove(filename)
            else:
                print >>sys.stderr, 'received message"%s"' %data
                server_name,iteration = data.split(" ")
                Threads = []
                t = threading.Thread(target=Ping_check, args=(server_name,iteration))
                t.setDaemon(True)
                Threads.append(t)
                t.start()

                t = threading.Thread(target=Hops_check, args=(server_name, ))
                t.setDaemon(True)
                Threads.append(t)
                t.start()

                for thread in range(len(Threads)):
                    Threads[thread].join()
                """
                print("^^^^^^^^^^^^---HOPS------PING---^^^^^^^^")
                print("HOPS = %d" %int(tmp_hops))
                print("PING = %f" %float(tmp_rtt))
                print("^^^^^^^^^^^^---HOPS------PING---^^^^^^^^")
                """
                if data:
                    msg_back = str(int(tmp_hops)) + " " + str(float(tmp_rtt))
                    print >>sys.stderr, 'sending data back to the client: %s' %msg_back
                    msg_back = encryption(msg_back)
                    connection.sendall(msg_back)
                else:
                    print >>sys.stderr, 'no more data from', client_address
                    break

    finally:
        # Clean up the connection
        connection.close()
