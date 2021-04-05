from TcpAttack import *
import time
#Your TcpAttack class should be named as TcpAttack
spoofIP='192.168.4.1' ; targetIP='192.168.4.64' #Will contain actual IP addresses in real script
start_time = time.time()
rangeStart=1 ; rangeEnd=1024 ; port=22
Tcp = TcpAttack(spoofIP,targetIP)
print("Scanning...")
#Tcp.scanTarget(rangeStart, rangeEnd)
end_time = time.time()
print("Ex time: "+str(end_time - start_time))
print("Attacking...")
if Tcp.attackTarget(port,10):
   print("Port was open for attack.")