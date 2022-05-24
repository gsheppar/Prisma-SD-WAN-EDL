#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import collections
import os
import datetime
import time
import json
import requests
import ipaddress



# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: EDL Prefix'
SCRIPT_VERSION = "v1"
EPOCH = datetime.datetime(1970, 1, 1)
SYSLOG_DATE_FORMAT = '%b %d %H:%M:%S'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN
    from cloudgenix_settings import GROUP
    from cloudgenix_settings import URL

except ImportError:
    CLOUDGENIX_AUTH_TOKEN = None
    GROUP = None
    URL = None
    
        
def update_security(cgx, url, security_group):
    
    try:
        response = requests.get(url)
    except:
        print("Failed to connect to " + str(url))
        return
    
    words = response.content.splitlines()
    subnets = [w.decode('utf-8') for w in words]
    prefix_list = []
    for subnet in subnets:
        try:
            ip = ipaddress.ip_network(subnet)
            prefix_list.append(subnet)
        except:
            print(str(subnet) + " is not an IP address")
    policy_id = None
    data = None
    for policy in cgx.get.ngfwsecuritypolicyglobalprefixes().cgx_content["items"]:
        if policy["name"] == security_group:
            policy_id = policy["id"]
            data = policy

    if len(prefix_list) == 0:
        print("EDL has no prefixes")
        return
         
    if policy_id:
        data["ipv4_prefixes"] = prefix_list
        resp = cgx.put.ngfwsecuritypolicyglobalprefixes(ngfwsecuritypolicyglobalprefix_id=policy_id, data=data)
        if not resp:
            print(str(jdout(resp)))
        else:
            print("Updating security prefix " + security_group + " with " + str(len(prefix_list)) + " prefixes")
    else:
        data = {"name":security_group,"tags":[],"ipv4_prefixes":prefix_list,"description":None}
        resp = cgx.post.ngfwsecuritypolicyglobalprefixes(data)
        if not resp:
            print(str(jdout(resp)))
        else:
            print("Creating security prefix " + security_group + " with " + str(len(prefix_list)) + " prefixes")
        
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # check for token
    if CLOUDGENIX_AUTH_TOKEN:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()
    else:
        print("No AUTH_TOKEN found")
        sys.exit()

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    
    while True:
        
        if cgx_session.tenant_id is None:
            if CLOUDGENIX_AUTH_TOKEN:
                cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
                if cgx_session.tenant_id is None:
                    print("AUTH_TOKEN login failure, please check token.")
                    sys.exit()
            else:
                print("No AUTH_TOKEN found")
                sys.exit()

        update_security(cgx_session, URL, GROUP)
        time.sleep(300)
   

if __name__ == "__main__":
    go()