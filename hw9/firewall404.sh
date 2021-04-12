#! /bin/sh 
# don't forget to use chmod +x jasonsfirewall.sh
# run sudo python3 jasonsfirewall.sh

# Homework Number: 9
# Name: Jason Park
# ECN Login: park1036
# Due Date: 4/6/2021

## some code borrowed from lecture 18 notes

## Remove previous stuff 
iptables -F # rules
iptables -X # chains

####################################################
# For outgoing packets, change source IP to my IP  #
# (see MASQUERADE target in the nat table)         #
####################################################
source_ip = "10.0.2.15"
#--to-source $source_ip
#modprobe ip_nat_ftp 
iptables -t nat -A POSTROUTING -o $ext_if -j MASQUERADE

################################################# 
# Block all new packets coming from yahoo.com   #
# (i.e. a packet that creates a new connection) #
#################################################
site = "yahoo.com"
iptables -A INPUT -s site -j REJECT 

#############################################################
# Block your computer from being pinged by all other hosts  #
# (Hint: ping uses ICMP Echo requests)                      #
#############################################################
icmp_types = "ping"
for icmp in $icmp_types; do 
    iptables -A INPUT -p icmp --icmp-type $icmp -j ACCEPT
done 

######################################################################### 
# Set up port-forwarding from an unused port of your choice to port 22  #
# You should be able to SSH into the machine using both ports           #
# (May need to enable connections on the unused port as well)           #
#########################################################################
iptables -t nat -A PREROUTING -i enp0s3 -p tcp --dport 135 -j REDIRECT --to-port 22

################################################################# 
# Allow for SSH access (port 22) to your machine from only the  # 
# engineering.purdue.edu domain                                 #
#################################################################
iptables -A -p tcp -s engineering.purdue.edu --destination-port 22 -j ACCEPT 

############################################################################
# Assuming you are running an HTTPD server on your machine that can make   #
# available your entire home directory to the outside world, write a rule  #
# for preventing DoS attacks by limiting connection requests to 30 per     #
# minute after a total of 60 connections have been made                    #
############################################################################
iptables -A FORWARD -i enp0s3 -p tcp -d 192.168.4.64 --dport 60 --syn -j ACCEPT

## Drop any other packets if they are not caught by the above rules
iptables -A -p all -j REJECT --reject-with icmp-host-prohibited