
import aiohttp
import asyncio

from modules.subdomain_modules.bevigil_subs import bevigil
from modules.subdomain_modules.thcrowd_subs import thcrowd
from modules.subdomain_modules.anubis_subs import anubisdb
from modules.subdomain_modules.thminer_subs import thminer
from modules.subdomain_modules.fb_subs import fb_cert
from modules.subdomain_modules.virustotal_subs import virust
from modules.subdomain_modules.shodan_subs import shodan
from modules.subdomain_modules.certspot_subs import certspot
from modules.subdomain_modules.wayback_subs import machine
from modules.subdomain_modules.sonar_subs import sonar
from modules.subdomain_modules.crtsh_subs import crtsh
from modules.subdomain_modules.htarget_subs import hackertgt

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

found = []


async def query(hostname, tout, conf_path):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			bevigil(hostname, conf_path, session),
			thcrowd(hostname, session),
			anubisdb(hostname, session),
			thminer(hostname, session),
			fb_cert(hostname, conf_path, session),
			virust(hostname, conf_path, session),
			shodan(hostname, conf_path, session),
			certspot(hostname, session),
			machine(hostname, session),
			sonar(hostname, session),
			hackertgt(hostname, session),
			crtsh(hostname)
		)
	await session.close()


def subdomains(hostname, tout, output, data, conf_path,user,target):
	global found
	result = {}
	result["username"]=user
	result["target"]=target
	print(result)

	print(f'\n{Y}[!] Starting Sub-Domain Enumeration...{W}\n')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout, conf_path))
	loop.close()

	found = [item for item in found if item.endswith(hostname)]
	valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
	from re import match
	found = [item for item in found if match(valid, item)]
	found = set(found)
	total = len(found)
	i=1
	if len(found) != 0:
		#print(f'\n{G}[+] {C}Results : {W}\n')
		for url in found:

			result[str(i)]=url
			
			i+=1

	print(f'\n{G}[+] {C}Total Unique Sub Domains Found : {W}{total}')
	
	
	return result
	
