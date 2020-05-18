import sys
import subprocess
import os
import socket
import threading
import urllib
import random
import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from Crypto.Cipher import AES

RECV_BUFFER_SIZE = 2048


Relays = {}
End_servers = {}
rtt_result = {}
hops_result = {}
relay_server_hops = {}
relay_server_rtt = {}
duplicate_rtt = []
duplicate_hops = []



sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

"""
def end_servers_split():
    file = open(sys.argv[2] , 'r')
    for line in file:
        x = line.split(", ")
        x[1] = x[1].replace('\n','')
        x[1] = x[1].replace('\r','')

        End_servers[x[1]] = x[0]
    file.close
"""

#Open file with end servers and save them in a dictionary
def end_servers_split():
    file = open(sys.argv[2],"r")
    for line in file:
        domain_address,name=line.split(", ")
        name = name.replace('\n','')
        name = name.replace('\r','')
        End_servers[name] = domain_address
    file.close

#Open file with relays and save them in a dictionary
def relays_split():
    file = open(sys.argv[4],"r")
    for line in file:
        relay_address,ip,port=line.split(" ")
        #name = name.replace('\n','')
        #name = name.replace('\r','')
        port = port.replace('\n','')
        Relays[relay_address] = (ip,int(port))
        #print("type port is ",type(port))
        """
        print("^^^^^^^^^^^^^^^^ IP ^^^^^^^^^^^^^^^")
        print(Relays[relay_address][0])
        print("^^^^^^^^^^^^^^^^ IP ^^^^^^^^^^^^^^^")
        """
    file.close


def Ping_check(name,times,check):
    if(check == "direct"):
        rtts = subprocess.Popen(["ping" , "-c" , str(times) , name], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
        #print(rtts)
        for line in iter(rtts.stdout.readline, ''):
            lastln=line
            #print(line)
        avgping=get_avg_ping(lastln)
        print("Direct avg ping %f" %float(avgping))
        rtt_result["direct"] = float(avgping)
    else:
#       print("ylophsh relay ping")
        rtts = subprocess.Popen(["ping" , "-c" , str(times) ,Relays[name][0]], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
        
        for line in iter(rtts.stdout.readline, ''):
            lastln=line
            #print(line)
        avgping=get_avg_ping(lastln)
        #print("ylophsh relay ping " + name)
        print("rtt for client -> %s is %f" %(name,float(avgping)))
        rtt_result[name] = float(avgping)


def Hops_check(name, check):
    if(check == "direct"):
        hops = subprocess.Popen(["traceroute" , name], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)            
        count = 0
        for i in iter(hops.stdout.readline, ''):
            #print(i)
            count = count + 1
        count = count - 1
        print("Direct Hops " + str(count))
        hops_result["direct"] = (count)
    else:
        #print("ylophsh relay hop")
        hops = subprocess.Popen(["traceroute" , Relays[name][0]], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
        count = 0
        for i in iter(hops.stdout.readline, ''):
            #print(i)
            count = count + 1
        #print("ylophsh relay hop " + name)
        print("hops for client -> %s is %d"%(name,count-1))
        hops_result[name] = (count-1)


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

#make private key and public key
random_number = Random.new().read
private_key = RSA.generate(2048, random_number)
public_key = private_key.publickey()

random_string = os.urandom(16)
symmetric_key = base64.b64encode(random_string)
cipher = AES.new(random_string)


#function msg_public_signature return a message with public key and signature
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
    message = base64.b64decode(message)
    decoded_message = cipher.decrypt(message).decode('utf-8')
    #decoded_message = cipher.decrypt(encrypted_msg)
    padding = decoded_message.count('@')
    #return decoded_message[padding:]
    return decoded_message[:len(decoded_message)-padding]

def send_to_relay(r_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (Relays[r_name][0], Relays[r_name][1])
    print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)
    
    try:
        msg = End_servers[name] + " " + iteration
        message = encryption(msg)
        sock.send(message)
        data = sock.recv(RECV_BUFFER_SIZE)
        data = decryption(data)
        print >>sys.stderr, 'received from %s : %s' %(r_name,data)
        hops, rtt = data.split(" ")
        relay_server_hops[r_name] = int(hops)
        relay_server_rtt[r_name] = float(rtt)
    finally:
        print >>sys.stderr, 'Not exist problem.Send message is complete and close connection\n'
        sock.close()

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@
relays_split()
"""
print("$$$$$$$$$$$$$$$$$ RELAYS $$$$$$$$$$$$$$$$$$$$\n")
print(Relays.items())
print("$$$$$$$$$$$$$$$$$ RELAYS $$$$$$$$$$$$$$$$$$$$\n")
"""
end_servers_split()

"""
print(len(End_servers))
print(End_servers.items())
k = "google"
#print(End_servers[k])

Ping_check(End_servers[k],3,"direct")
Hops_check(End_servers[k],"direct")
"""

#--------------------------------------------------------------
#------------SOCKETS - RELAYS -----------------------------------
"""
for k in Relays.keys():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (Relays[k][0],Relays[k][1])
    print "Connect with alias %s , address %s and port %d \n" % (k,Relays[k][0],Relays[k][1])
    sock.connect(server_address)

    message = "End_servers[name] iteration"
    sock.sendall(message)

    data = sock.recv(RECV_BUFFER_SIZE)
    print "Received data %s" % data
    print "------------------------"
"""


for name in Relays.keys():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address_port = (Relays[name][0],Relays[name][1])
    sock.connect(server_address_port)
    
    try:
        message = msg_public_signature();
        #print("message to send with public key and signature %s\n" %message)
        sock.send(message)

        data = sock.recv(RECV_BUFFER_SIZE)
        
        trash,relay_pkey,relay_signature = data.split("$$")

        relay_public_key = RSA.importKey(relay_pkey)
        hash_result = SHA256.new(relay_pkey).digest()
        if relay_public_key.verify(hash_result,eval(relay_signature)):
            print "client received correctly %s's public key" %name
            message = relay_public_key.encrypt(symmetric_key,16)
            hash_result = SHA256.new(symmetric_key).digest()
            signature =  private_key.sign(hash_result,'')
            message = str(message) + "$$" + str(signature)
            sock.send(message)
        else:
            print "client failed to receive relay's the public key "        
    
    finally:
        print >>sys.stderr, 'Not exist problem.Send message is complete.\n'
        sock.close()


arguments = raw_input("Give name server, iteration and type of test: \n")
while arguments:
    name,iteration,test = arguments.split(" ")

    if not any(alias == name for alias in End_servers.keys()) :
        print("False server name.Please try again.")
        arguments = raw_input("Give name server, iteration and type of test: \n")
        continue
    else:
        print("^^^^^^^^^^^^^^^^^ FIND ALIAS ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
        if(iteration.isdigit() != True):
            print("False,input interation is not digit.Please try again.")
            arguments = raw_input("Give name server, iteration and type of test: \n")
            continue
        else:
            if (int(iteration) == 0):
                print("False iteration number =0 .Please try again.")
                arguments = raw_input("Give name server, iteration and type of test: \n")
                continue
            if ((test!="latency") and (test!="hops")):
                print("False, type of test.Please try again.")
                arguments = raw_input("Give name server, iteration and type of test: \n")
                continue                

    Threads = []
    print("Make ping and traceroute for end serrver - direct")
    #server = End_servers[name]
    print("&&&&&&&&&&&&&&")
    print(End_servers[name])
    print("&&&&&&&&&&&&&&")

    #Ping_check(End_servers[name],iteration,"direct")
    t = threading.Thread(target=Ping_check, args=(End_servers[name],iteration,"direct"))
    t.setDaemon(True)
    Threads.append(t)
    t.start()

    t = threading.Thread(target=Hops_check, args=(End_servers[name],"direct"))
    t.setDaemon(True)
    Threads.append(t)
    t.start()
    #--------------------------------------------
    print("Make ping and traceroute for relays")

    for k in Relays.keys():
        print "****************%s" % k , "****************"
        #Ping_check(k,iteration,"dsad")
        t = threading.Thread(target=Ping_check, args=(k,iteration,"relay"))
        t.setDaemon(True)
        Threads.append(t)
        t.start()
        #Hops_check(k, "asadds")
        t = threading.Thread(target=Hops_check, args=(k,"relay"))
        t.setDaemon(True)
        Threads.append(t)
        t.start()

        t = threading.Thread(target=send_to_relay, args=(k, ))
        t.setDaemon(True)
        Threads.append(t)
        t.start()
        

    for thread in range(len(Threads)):
            Threads[thread].join()

    
    if (rtt_result["direct"] == -1):
        print"Please try again, problem with tests."
        arguments = raw_input("Give name server, iteration and type of test: \n")
        continue

    for name in relay_server_hops.keys():
        rtt_result[name] = rtt_result[name] + relay_server_rtt[name]
        hops_result[name] = hops_result[name] + relay_server_hops[name]

    print("&&&&&&&&&& results direct rtt and hops &&&&&&&&&")
    print("direct rtt = %f" %rtt_result["direct"])
    print("direct hops = %d" %hops_result["direct"])

    print("&&&&&&&&&& results relay rtt and hops &&&&&&&&&")
    for name in relay_server_hops.keys():
        print("name : %s total rtt = %f" %(name, rtt_result[name]))
        print("name : %s total hops = %d" %(name, hops_result[name]))

    if (test == "latency"):
        key_min_rtt = min(rtt_result.keys(), key=(lambda k: rtt_result[k]))
        min_rtt = rtt_result[key_min_rtt]
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print('Minimum rtt: %f' %min_rtt)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        duplicate_rtt_count = -1
        duplicate_hops_count = -1
        for name in rtt_result.keys():
            if (min_rtt == rtt_result[name]):
                duplicate_rtt_count = duplicate_rtt_count + 1
                duplicate_rtt.append(name)
                """if duplicate_rtt== 0 then is ok, if duplicate_rtt>=1 then there are more than one minimum"""
        if(duplicate_rtt_count == 0):
            selected = key_min_rtt
        else:
            key_min_hops = min(hops_result.keys(), key=(lambda k: hops_result[k]))
            min_hops = hops_result[key_min_hops]  
            for name in rtt_result.keys():
                if (min_hops == hops_result[name]):
                    duplicate_hops_count = duplicate_hops_count + 1
                    duplicate_hops.append(name)
            if(duplicate_hops_count == 0):
                selected = key_min_hops
            else:
                rand = random.randint(0,1)
                if(rand == 0):
                    index = random.randint(0, duplicate_hops_count)
                    selected = duplicate_hops[index]
                else:
                    index = random.randint(0, duplicate_rtt_count)
                    selected = duplicate_rtt[index]             
    else:
        key_min_hops = min(hops_result.keys(), key=(lambda k: hops_result[k]))
        min_hops = hops_result[key_min_hops]
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print('Minimum hops: %f' %min_hops)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        duplicate_rtt_count = -1
        duplicate_hops_count = -1
        for name in hops_result.keys():
            if (min_hops == hops_result[name]):    
                duplicate_hops_count = duplicate_hops_count + 1
                duplicate_hops.append(name)
        if(duplicate_hops_count == 0):
            selected = key_min_hops
        else:
            key_min_rtt = min(rtt_result.keys(), key=(lambda k: rtt_result[k]))
            min_rtt = rtt_result[key_min_rtt]
            for name in hops_result.keys():
                if (min_rtt == rtt_result[name]):
                    duplicate_rtt_count = duplicate_rtt_count + 1
                    duplicate_rtt.append(name)
            if(duplicate_rtt_count == 0):
                selected = key_min_rtt
            else:
                rand = random.randint(0,1)
                if(rand == 0):
                    index = random.randint(0, duplicate_rtt_count)
                    selected = duplicate_rtt[index]
                else:
                    index = random.randint(0, duplicate_hops_count)
                    selected = duplicate_hops[index]

    print("SELECTED: %s" %selected)
    file_down = open("files2download.txt","r")
    print "\nPlease, select one link of them\n"
    for line in file_down:
        print(line)
    
    if (selected == "direct"):
        print ("Direct is the right path ")
        url = raw_input("Please, give url to download the file.\n")
        file_name = "image" + url[-4:]
        start_time = time.time()
        urllib.urlretrieve(url, file_name)
        total_time = time.time() - start_time
        print "Download's time: %f" %total_time , " seconds"
        print ("Image has been downloaded")
    else:
    
        url = raw_input("Please, give url to download the file.\n")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (Relays[selected])
        """server_address = (Relays["anafi"])"""
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        sock.connect(server_address)
        try:
            msg_url = "dwnld_url " + url
            message = encryption(msg_url)
            sock.send(message)
            download_file = open ('image' + url[-4:], 'wb')
            start_time = time.time()
            data = sock.recv(RECV_BUFFER_SIZE)
            

            while (data):
                #data = decryption(data)
                download_file.write(data)
                data = sock.recv(RECV_BUFFER_SIZE)
                

            download_file.close()

            total_time = time.time() - start_time
            print ("Image has been downloaded")
            print "Download's time: %f" % total_time , "seconds"
        finally:
            print >>sys.stderr, 'Not exist problem.Send message is complete and close connection\n'
            sock.close()

    arguments = raw_input("Give name server, iteration and type of test: \n")
