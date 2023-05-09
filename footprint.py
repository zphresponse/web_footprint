import builtwith
import requests
from termcolor import colored
import pyfiglet
import nmap
import sys
import os
import socket

result = pyfiglet.figlet_format("ZYBER PH", font = "slant") 
print(colored(result, "green"))

print(colored(" [ RESPONSE TEAM ] - [ WEB FOOTPRINTER ]\n\n", "red"))


site = input(" > Enter site without http/https: ")
print(colored("\n\n > Gathering information from the host.", "green"))

r = requests.get("http://"+site)
xsite = r.url

x = builtwith.parse(xsite)

print("\n Built Technology\n")
print('----------------------------------------------------')
for e, v in x.items():
 print(colored(" "+e.upper(),"yellow")," : ", v)

print('----------------------------------------------------')
print(colored("\n > Foot printing hosts..", "green"))
print(colored("\n > Scanning open ports from 22-8080", "cyan"))

ip = socket.gethostbyname(site)

try:
    nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

nm.scan(ip, '22-8080')      # scan host 127.0.0.1, ports from 22 to 443
nm.command_line()                   # get command line used for the scan : nmap -oX - -p 22-443 127.0.0.1
nm.scaninfo()                       # get nmap scan informations {'tcp': {'services': '22-443', 'method': 'connect'}}
nm.all_hosts()                      # get all hosts that were scanned
nm[ip].hostname()          # get one hostname for host 127.0.0.1, usualy the user record
nm[ip].hostnames()         # get list of hostnames for host 127.0.0.1 as a list of dict [{'name':'hostname1', 'type':'PTR'}, {'name':'hostname2', 'type':'user'}]
nm[ip].state()             # get state of host 127.0.0.1 (up|down|unknown|skipped) 
nm[ip].all_protocols()     # get all scanned protocols ['tcp', 'udp'] in (ip|tcp|udp|sctp)
if ('tcp' in nm[ip]):
    list(nm[ip]['tcp'].keys()) # get all ports for tcp protocol

nm[ip].all_tcp()           # get all ports for tcp protocol (sorted version)
nm[ip].all_udp()           # get all ports for udp protocol (sorted version)
nm[ip].all_ip()            # get all ports for ip protocol (sorted version)
nm[ip].all_sctp()          # get all ports for sctp protocol (sorted version)
if nm[ip].has_tcp(22):     # is there any information for port 22/tcp on host 127.0.0.1
    nm[ip]['tcp'][22]          # get infos about port 22 in tcp on host 127.0.0.1
    nm[ip].tcp(22)             # get infos about port 22 in tcp on host 127.0.0.1
    nm[ip]['tcp'][22]['state'] # get state of port 22/tcp on host 127.0.0.1 (open


# a more usefull example :
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print(' Host : {0} ({1})'.format(host, nm[host].hostname()))
    print(' State : {0}'.format(nm[host].state()))

    for proto in nm[host].all_protocols():
        print('----------')
        print(' Protocol : {0}'.format(proto))

        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print(' port : {0}\tstate : {1}\tinfo : {2}'.format(colored(port,"yellow"), colored(nm[host][proto][port]['state'],"green"), colored(nm[host][proto][port]['name'], "yellow") + " -- " + colored(nm[host][proto][port]['product'], "green") + " -- " + colored(nm[host][proto][port]['version'],"yellow")))


print('----------------------------------------------------')
