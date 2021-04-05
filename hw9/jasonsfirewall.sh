#! /bin/sh 
# don't forget to use chmod +x jasonsfirewall.sh
# run sudo ./jasonsfirewall.sh I think

## Remove previous stuff 
iptables -t filter -F # rules
iptables -t filter -X # chains

####################################################
# For outgoing packets, change source IP to my IP  #
# (see MASQUERADE target in the nat table)         #
####################################################
source_ip = "10.0.2.15"
modprobe ip_nat_ftp
iptables -t nat -A POSTROUTING -o $ext_if -j MASQUERADE --to-source $source_ip

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

######################################################################### 
# Set up port-forwarding from an unused port of your choice to port 22  #
# You should be able to SSH into the machine using both ports           #
# (May need to enable connections on the unused port as well)           #
#########################################################################

################################################################# 
# Allow for SSH access (port 22) to your machine from only the  # 
# engineering.purdue.edu domain                                 #
#################################################################

############################################################################
# Assuming you are running an HTTPD server on your machine that can make   #
# available your entire home directory to the outside world, write a rule  #
# for preventing DoS attacks by limiting connection requests to 30 per     #
# minute after a total of 60 connections have been made                    #
############################################################################

## Drop any other packets if they are not caught by the above rules