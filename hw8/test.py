from TcpAttack import *
import time
#Your TcpAttack class should be named as TcpAttack
spoofIP='128.46.4.82' ; targetIP='128.46.4.82' #Will contain actual IP addresses in real script
start_time = time.time()
rangeStart=1 ; rangeEnd=1024 ; port=22
Tcp = TcpAttack(spoofIP,targetIP)
print("Scanning...")
Tcp.scanTarget(rangeStart, rangeEnd)
end_time = time.time()
print("Ex time: "+str(end_time - start_time))
print("Attacking...")
if Tcp.attackTarget(port,10):
    print('port was open to attack')