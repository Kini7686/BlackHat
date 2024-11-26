#!/usr/bin/env python3

import re
import bs4
import lxml
import json
import asyncio
import requests
import threading
import tldextract
from datetime import date
#from modules.export import export
requests.packages.urllib3.disable_warnings()

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

user_agent = {'User-Agent': 'FinalRecon'}

soup = ''
result={}
total = []
r_total = []
sm_total = []
js_total = []
css_total = []
int_total = []
ext_total = []
img_total = []
js_crawl_total = []
sm_crawl_total = []


def crawler(target, output, data):
	global soup, r_url, sm_url, result
	print(f'\n{Y}[!] Starting Crawler...{W}\n')

	try:
		rqst = requests.get(target, headers=user_agent, verify=False, timeout=10)
	except Exception as e:
		print(f'{R} [-] Exception : {C}{e}{W}')
		return

	sc = rqst.status_code
	if sc == 200:
		page = rqst.content
		soup = bs4.BeautifulSoup(page, 'lxml')

		protocol = target.split('://')
		protocol = protocol[0]
		temp_tgt = target.split('://')[1]
		pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'
		custom = bool(re.match(pattern, temp_tgt))
		if custom is True:
			r_url = f'{protocol}://{temp_tgt}/robots.txt'
			sm_url = f'{protocol}://{temp_tgt}/sitemap.xml'
			base_url = f'{protocol}://{temp_tgt}'
		else:
			ext = tldextract.extract(target)
			hostname = '.'.join(part for part in ext if part)
			base_url = f'{protocol}://{hostname}'
			r_url = f'{base_url}/robots.txt'
			sm_url = f'{base_url}/sitemap.xml'

		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		tasks = asyncio.gather(
			robots(r_url, base_url, data, output),
			sitemap(sm_url, data, output),
			css(target, data, output),
			js(target, data, output),
			internal_links(target, data, output),
			external_links(target, data, output),
			images(target, data, output),
			sm_crawl(data, output),
			js_crawl(data, output))
		loop.run_until_complete(tasks)
		loop.close()
		return result
		#stats(output, data)
	else:
		print(f'{R}[-] {C}Status : {W}{sc}')


def url_filter(target, link):
	if all([link.startswith('/') is True, link.startswith('//') is False]):
		ret_url = target + link
		return ret_url
	else:
		pass

	if link.startswith('//') is True:
		ret_url = link.replace('//', 'http://')
		return ret_url
	else:
		pass

	if all([
		link.find('//') == -1,
		link.find('../') == -1,
		link.find('./') == -1,
		link.find('http://') == -1,
		link.find('https://') == -1]
	):
		ret_url = f'{target}/{link}'
		return ret_url
	else:
		pass

	if all([
		link.find('http://') == -1,
		link.find('https://') == -1]
	):
		ret_url = link.replace('//', 'http://')
		ret_url = link.replace('../', f'{target}/')
		ret_url = link.replace('./', f'{target}/')
		return ret_url
	else:
		pass
	return link

async def robots(robo_url, base_url, data, output):
	global r_total, result
	print(f'{G}[+] {C}Looking for robots.txt{W}', end='', flush=True)

	try:
		r_rqst = requests.get(robo_url, headers=user_agent, verify=False, timeout=10)
		r_sc = r_rqst.status_code
		if r_sc == 200:
			print(G + '['.rjust(9, '.') + ' Found ]' + W)
			print(f'{G}[+] {C}Extracting robots Links{W}', end='', flush=True)
			r_page = r_rqst.text
			r_scrape = r_page.split('\n')
			for entry in r_scrape:
				if any([
					entry.find('Disallow') == 0,
					entry.find('Allow') == 0,
					entry.find('Sitemap') == 0]):

					url = entry.split(': ')
					try:
						url = url[1]
						url = url.strip()
						tmp_url = url_filter(base_url, url)
						if tmp_url is not None:
							r_total.append(url_filter(base_url, url))
						if url.endswith('xml') is True:
							sm_total.append(url)
					except Exception:
						pass
			
			result.setdefault('robots', []).append(r_total)

			
		elif r_sc == 404:
			print(R + '['.rjust(9, '.') + ' Not Found ]' + W)
		else:
			print(R + '['.rjust(9, '.') + ' {} ]'.format(r_sc) + W)
	except Exception as e:
		print(f'\n{R}[-] Exception : {C}{e}{W}')


async def sitemap(sm_url, data, output):
	global sm_total, result
	print(f'{G}[+] {C}Looking for sitemap.xml{W}', end='', flush=True)
	try:
		sm_rqst = requests.get(sm_url, headers=user_agent, verify=False, timeout=10)
		sm_sc = sm_rqst.status_code
		if sm_sc == 200:
			print(G + '['.rjust(8, '.') + ' Found ]' + W)
			print(f'{G}[+] {C}Extracting sitemap Links{W}', end='', flush=True)
			sm_page = sm_rqst.content
			sm_soup = bs4.BeautifulSoup(sm_page, 'xml')
			links = sm_soup.find_all('loc')
			for url in links:
				url = url.get_text()
				if url is not None:
					sm_total.append(url)
			result.setdefault('sitemap', []).append(sm_total)
			
		elif sm_sc == 404:
			print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
		else:
			print(f'{R}{"[".rjust(8, ".")} Status Code : {sm_sc} ]{W}')
	except Exception as e:
		print(f'\n{R}[-] Exception : {C}{e}{W}')


async def css(target, data, output):
	global css_total, result
	print(f'{G}[+] {C}Extracting CSS Links{W}', end='', flush=True)
	css = soup.find_all('link', href=True)

	for link in css:
		url = link.get('href')
		if url is not None and '.css' in url:
			css_total.append(url_filter(target, url))
	result.setdefault('css', []).append(css_total)
	


async def js(target, data, output):
	global total, js_total, result
	print(f'{G}[+] {C}Extracting Javascript Links{W}', end='', flush=True)
	scr_tags = soup.find_all('script', src=True)

	for link in scr_tags:
		url = link.get('src')
		if url is not None and '.js' in url:
			tmp_url = url_filter(target, url)
			if tmp_url is not None:
				js_total.append(tmp_url)
	result.setdefault('js', []).append(js_total)
	


async def internal_links(target, data, output):
	global total, int_total, result
	print(f'{G}[+] {C}Extracting Internal Links{W}', end='', flush=True)

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url is not None:
			if domain in url:
				int_total.append(url)
	result.setdefault('internal link', []).append(int_total)
	


async def external_links(target, data, output):
	global total, ext_total, result
	print(f'{G}[+] {C}Extracting External Links{W}', end='', flush=True)

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url is not None:
			if domain not in url and 'http' in url:
				ext_total.append(url)
	result.setdefault('external link', []).append(ext_total)
	


async def images(target, data, output):
	global total, img_total, result
	print(f'{G}[+] {C}Extracting Images{W}', end='', flush=True)
	image_tags = soup.find_all('img')

	for link in image_tags:
		url = link.get('src')
		if url is not None and len(url) > 1:
			img_total.append(url_filter(target, url))
	result.setdefault('images', []).append(img_total)
	


async def sm_crawl(data, output):
	global sm_crawl_total, result
	print(f'{G}[+] {C}Crawling Sitemaps{W}', end='', flush=True)

	threads = []

	def fetch(site_url):
		try:
			sm_rqst = requests.get(site_url, headers=user_agent, verify=False, timeout=10)
			sm_sc = sm_rqst.status_code
			if sm_sc == 200:
				sm_data = sm_rqst.content.decode()
				sm_soup = bs4.BeautifulSoup(sm_data, 'xml')
				links = sm_soup.find_all('loc')
				for url in links:
					url = url.get_text()
					if url is not None:
						sm_crawl_total.append(url)
			elif sm_sc == 404:
				# print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
				pass
			else:
				# print(R + '['.rjust(8, '.') + ' {} ]'.format(sm_sc) + W)
				pass
		except Exception:
			# print(f'\n{R}[-] Exception : {C}{e}{W}')
			pass

	for site_url in sm_total:
		if site_url != sm_url:
			if site_url.endswith('xml') is True:
				t = threading.Thread(target=fetch, args=[site_url])
				t.daemon = True
				threads.append(t)
				t.start()

	for thread in threads:
		thread.join()
	result.setdefault('sm_crwal', []).append(sm_crawl_total)
	


async def js_crawl(data, output):
	global js_crawl_total, result
	print(f'{G}[+] {C}Crawling Javascripts{W}', end='', flush=True)

	threads = []

	def fetch(js_url):
		try:
			js_rqst = requests.get(js_url, headers=user_agent, verify=False, timeout=10)
			js_sc = js_rqst.status_code
			if js_sc == 200:
				js_data = js_rqst.content.decode()
				js_data = js_data.split(';')
				for line in js_data:
					if any(['http://' in line, 'https://' in line]):
						found = re.findall(r'\"(http[s]?://.*?)\"', line)
						for item in found:
							if len(item) > 8:
								js_crawl_total.append(item)
		except Exception as e:
			print(f'\n{R}[-] Exception : {C}{e}{W}')

	for js_url in js_total:
		t = threading.Thread(target=fetch, args=[js_url])
		t.daemon = True
		threads.append(t)
		t.start()

	for thread in threads:
		thread.join()
	result.setdefault('js crawl', []).append(js_crawl_total)
	
target='https://slrtce.in'
output={}
data ={}
res=crawler(target, output, data)
print(type(res))