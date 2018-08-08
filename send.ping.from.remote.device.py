import paramiko
from paramiko import client
paramiko.util.log_to_file('/tmp/paramiko.log')
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
from threading import Thread
import sys
import time
from socket import *


#
#This script fingerprints a remote device. It meta that
#can be used to create by creating a compound 
#signature of its Ping payload, kernel version, and ssh version.
#
#
#This script must be ran with sudo-
#$>sudo python send.ping.from.remote.device.py
#
#


#########Notes
    #rawLayer = pkt[Raw].show()
    #ls(pkt)
    #Get and print pkt.show() Raw/Load string.
    #rawLoad = pkt.sprintf("{Raw:%Raw.load%\n}")
    #print rawLoad

    #payload = str(payload).encode("HEX")
    #print payload

    #rawLayer = pkt.getlayer(Raw).load
    #pkt.show()
    #pkt[Raw].show()
    #print str(pkt.getlayer(Raw)
    #icmpPkt = pkt[ICMP]
    #payload = str(payload).encode("HEX")






##Get SSH Version
#serverIp = "192.168.1.1"
serverIp = "192.168.1.2"
serverPort = 22

s = socket(AF_INET, SOCK_STREAM)

s.connect((serverIp, serverPort))
s.send('Hello world')
sshbanner = s.recv(2048)







#Print "TCP/IP sniffing started..."
def printsniffingstarted():
    print(" ")
    print("TCP/IP sniffing started...please wait.")
    print(" ")




#Print "Identifying device..."
def printidentifyingdevice():
    print(" ")
    print("Identifying device...please wait.")
    print(" ")
    devicesshver()



#Print "Sending pings..."
def printsendingpings():
    print(" ")
    print("Sending pings...please wait.")
    print(" ")
    print(" ")







#Print "Generating fps..."
def printgeneratingfp():
    print (" ")
    print (" ")
    print ("Generating ICMP Ping fingerprint...please wait.")
    print (" ")




#Setup SSH connection.
class ssh:
    client = None

    def __init__(self, address, username, password, timeout):
        #printsniffingstarted()
        #printsendingpings()


        #Create a new SSH client.
        self.client = client.SSHClient()

        #The following line is required if you want the script to access servers that are not in the known_hosts file.
        self.client.set_missing_host_key_policy(client.AutoAddPolicy())
 
        #Make the connection.
        #self.client.connect("192.168.1.1", username="root", password="blank", look_for_keys="False", timeout=10)
        self.client.connect("192.168.1.2", username="root", password="blank", look_for_keys="False", timeout=10)


    #This block is used for sending pings.
    def sendCommand(self, command):
        printsniffingstarted()
        printsendingpings()

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



    #This block is used for getting kernel version.
    def sendCommand1(self, command1):
        #Check if connection is made previously
        self.alldata1 = ""
        if(self.client):
            stdin, stdout, stderr = self.client.exec_command(command1)
            while not stdout.channel.exit_status_ready():
                #Print stdout data when available
                if stdout.channel.recv_ready():
                    #Retrieve the first 1024 bytes
                    self.alldata1 = stdout.channel.recv(1024)
                    while stdout.channel.recv_ready():
                        #Retrieve the next 1024 bytes
                        self.alldata1 += stdout.channel.recv(1024)


                    #Print as string with utf8 encoding
                    #print(str(self.alldata1))

        else:
            print("Connection not opened.")




#Sleep.
def sleepdelay():
    time.sleep(.00025)
    sniffing()




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
    payloadfp = findicmppadding(payload)
    icmppayload(payload)









#Get the Raw/Load layer's fingerprint. 
def findicmppadding(payload):
    sleepdelay()
    for i in xrange(0, len(payload) - 2):
        if (ord(payload[i]) == ord(payload[i+1]) - 1) and (ord(payload[i]) == (ord(payload[i+2]) - 2)):
            payloadfpfirstcharhex = hex(ord(payload[i]))
            payloadfpsecondcharhex = hex(ord(payload[i]) + 1)
            payloadfpthirdcharhex = hex(ord(payload[i]) + 2)
 

            payloadfpfirstchar = ord(payload[i])
            payloadfpsecondchar = ord(payload[i]) + 1
            payloadfpthirdchar = ord(payload[i]) + 2

            print (" ")
            print (" ")
            print ("Ping fingerprint leading characters.")
            print (payloadfpfirstcharhex), (payloadfpsecondcharhex), (payloadfpthirdcharhex)
            print (" ")
 
            print (" ")
            print ("Ping fingerprint.")
            payloadfp = (payload[i: ]).encode("HEX")
            print payloadfp
            print (" ")
            return payloadfp
            exit()





#Print the entire payload.
def icmppayload(payload):
    print (" ")
    print ("ICMP Raw protocol layer.")
    payload = str(payload).encode("HEX")
    print (payload)
    print (" ")
    print (" ")
    printidentifyingdevice()





#Display OS Kernel and SSH version of remote device.
def devicesshver():
    print ""
    print ""
    print ("OS Kernel version.")
    print kernelver
    #print(str(connection1.alldata1))
    print ("SSH version.")
    print sshbanner








#Start sniffing.
s = threading.Thread(target=sniffing)
s.start()








#SSH to remote device and send Pings.
#myIp = "192.168.1.1"
myIp = "192.168.1.2"
sshRemoteUser = "root"
sshRemotePwd = "blank"
remoteCommand = "ping -c 1 192.168.1.99"
timeOut = 0
connection = ssh(myIp, sshRemoteUser, sshRemotePwd, timeOut)
connection.sendCommand(remoteCommand)






#SSH to remote device and get kernel version.
myIp1 = "192.168.1.1"
sshRemoteUser1 = "root"
sshRemotePwd1 = "blank"
remoteCommand1 = "uname -r"
timeOut1 = 0
connection1 = ssh(myIp1, sshRemoteUser1, sshRemotePwd1, timeOut1)
connection1.sendCommand1(remoteCommand1)
kernelver = (str(connection1.alldata1))



printgeneratingfp()



exit()

