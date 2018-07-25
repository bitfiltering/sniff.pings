import paramiko
from paramiko import client
paramiko.util.log_to_file('/tmp/paramiko.log')
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
from threading import Thread
import time
import sys


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
#




#Create an SSH client, connect to destination.
class ssh:
    client = None

    def __init__(self, address, username, password, timeout):
        print("Connecting to server.")

        #Create a new SSH client.
        self.client = client.SSHClient()

        #The following line is required if you want the script to be able to access servers that's not yet in the known_hosts file.
        self.client.set_missing_host_key_policy(client.AutoAddPolicy())
 
        #Make the connection
        self.client.connect("192.168.1.1", username="root", password="somepassword", look_for_keys="False", timeout=10)


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





def findicmppadding(payload):
    for i in xrange(0, len(payload) - 2):
        if (ord(payload[i]) == ord(payload[i+1]) - 1) and (ord(payload[i] == ord(payload[i+2]) - 2):
            padding = payload[i:]
            return (i, ord(padding[0]), len(padding))





#Sniffing
def sniffing():
    #sniff(iface='enp0s25', prn= lambda x: filter="icmp and host 192.168.1.1", store=0, count=10)
    sniff(iface='enp0s25', store=0, count=50, prn=icmpPayload)
    #time.sleep(1)






#Parse ICMP payload
def icmpPayload(pkt):
    for p in pkt:
        if ICMP in p:
            if pkt['ICMP'].type == 8:    #8=Echo Request
                     try:
                         paddingdesc = findicmppadding(pkt['ICMP'].load)

                     execept AttributeError:
                         pass





#Start sniffing.
s = threading.Thread(target=sniffing)
s.start()






#SSH to remote device and send Pings.
myIp = "192.168.1.1"
sshRemoteUser = "root"
sshRemotePwd = "somepassword"
remoteCommand = "ping -c 1 192.168.1.2"
timeOut = 0
connection = ssh(myIp, sshRemoteUser, sshRemotePwd, timeOut)
connection.sendCommand(remoteCommand)


exit()

