import paramiko
from paramiko import client
paramiko.util.log_to_file('/tmp/paramiko.log')
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
from threading import Thread
import sys



#Script created 7/12/18
#Last modified 7/25/18
#
#This script uses SSH to connect to a remote device.
#It then sends ICMP ping packets from it back to your pc.
#The Ping's payload is displayed and used to identify
#the remote device.
#
#This script must be ran with sudo-
#$>sudo python send.ping.from.remote.device.py
#
#
#




#Setup SSH connection.
class ssh:
    client = None

    def __init__(self, address, username, password, timeout):
        print("Sending pings...please wait")
        print(" ")

        #Create a new SSH client.
        self.client = client.SSHClient()

        #The following line is required if you want the script to access servers that are not in the known_hosts file.
        self.client.set_missing_host_key_policy(client.AutoAddPolicy())
 
        #Make the connection.
        self.client.connect("192.168.1.1", username="root", password="thepassword", look_for_keys="False", timeout=10)


    def sendCommand(self, command):

        #Check if connection is made previously
        if(self.client):
            stdin, stdout, stderr = self.client.exec_command(command)
            while not stdout.channel.exit_status_ready():
                #Print stdout data when available
                if stdout.channel.recv_ready():
                    #Retrieve the first 1024 bytes
                    alldata = stdout.channel.recv(1024)
                    while stdout.channel.recv_ready():
                        #Retrieve the next 1024 bytes
                        alldata += stdout.channel.recv(1024)

                    #Print as string with utf8 encoding
                    print(str(alldata))

        else:
            print("Connection not opened.")






#Sniffing
def sniffing():
    #sniff(iface='enp0s25', prn= lambda x: filter="icmp and host 192.168.1.1", store=0, count=10)
    sniff(iface='enp0s25', store=0, count=50, prn=icmpPayload)






#Get the ICMP Echo Request
def icmpPayload(pkt):
    for p in pkt:
        if ICMP in p:
            if pkt['ICMP'].type == 8:    #8=Echo Request
                findicmprawloadlayer(pkt)





#Get the ICMP Raw/Load layer.
def findicmprawloadlayer(pkt):
    payload = pkt.getlayer(Raw).load
    findicmppadding(payload)





#Get the Raw/Load layer's fingerprint. 
def findicmppadding(payload):
    for i in xrange(0, len(payload) - 2):
        if (ord(payload[i]) == ord(payload[i+1]) - 1) and (ord(payload[i]) == (ord(payload[i+2]) - 2)):
            payloadfirstcharhex = hex(ord(payload[i]))
            payloadsecondcharhex = hex(ord(payload[i]) + 1)
            payloadthirdcharhex = hex(ord(payload[i]) + 2)
 
            payloadfirstchar = ord(payload[i])
            payloadsecondchar = ord(payload[i]) + 1
            payloadthirdchar = ord(payload[i]) + 2

            print (" ")
            print (" ")
            print ("ICMP fingerprint leading characters.")
            print (payloadfirstcharhex), (payloadsecondcharhex), (payloadthirdcharhex)
            print (" ")



            print (" ")
            print (" ")
            print ("ICMP fingerprint.")
            payloadentire = (payload[i: ]).encode("HEX")
            print payloadentire
            print (" ")
            print (" ")


            icmppayload(payload)
            exit()





#Print the entire payload.
def icmppayload(payload):
    print (" ")
    print ("ICMP full Raw layer.")
    payload = str(payload).encode("HEX")
    print (payload)
    print (" ")
    print (" ")
    exit()





#Start sniffing.
s = threading.Thread(target=sniffing)
s.start()





#SSH to remote device and send Pings.
myIp = "192.168.1.1"
sshRemoteUser = "root"
sshRemotePwd = "thepassword"
remoteCommand = "ping -c 1 192.168.1.99"
timeOut = 0
connection = ssh(myIp, sshRemoteUser, sshRemotePwd, timeOut)
connection.sendCommand(remoteCommand)



exit()

