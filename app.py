from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_pymongo import PyMongo
import ipaddress
from os import name
import socket

import requests

import tldextract
import re
import bs4
import lxml
import json
import asyncio

import threading

from datetime import date

from flask_bcrypt import Bcrypt
from modules import head,sslinfo,dns,wayback,whois
from modules.subdom import subdomains
app = Flask(__name__)

mongo = PyMongo(app, uri="mongodb://localhost:27017/project")
user=mongo.db.user
bcrypt = Bcrypt(app)
dnsrec=dns.dnsrec
headers=head.headers
cert=sslinfo.cert
timetravel=wayback.timetravel
whois_lookup=whois.whois_lookup

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
	result["username"]=session['username']
	result["target"]=target
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
			result["robots"]=r_total
			#result.setdefault('robots', []).append(r_total)

			
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
			result["sitemap"]=sm_total
			#result.setdefault('sitemap', []).append(sm_total)
			
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
	result["css"]=css_total
	#result.setdefault('css', []).append(css_total)
	


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
	result["js"]=js_total
	#result.setdefault('js', []).append(js_total)
	


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
	result["internal_link"]=int_total
	#result.setdefault('internal link', []).append(int_total)
	


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
	result["external_link"]=ext_total
	#result.setdefault('external link', []).append(ext_total)
	


async def images(target, data, output):
	global total, img_total, result
	print(f'{G}[+] {C}Extracting Images{W}', end='', flush=True)
	image_tags = soup.find_all('img')

	for link in image_tags:
		url = link.get('src')
		if url is not None and len(url) > 1:
			img_total.append(url_filter(target, url))
	result["images"]=img_total
	#result.setdefault('images', []).append(img_total)
	


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
	result["sm_crawl"]=sm_crawl_total
	#result.setdefault('sm_crwal', []).append(sm_crawl_total)
	


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
	result["js_crawl"]=js_crawl_total
	#result.setdefault('js crawl', []).append(js_crawl_total)

#home page
@app.route('/', methods=['GET'])
def form():
	if 'username' in session:
		return redirect(url_for('home'))
	return render_template('homepage.html')


    
@app.route('/home')
def home():
	return render_template('dashboard.html',data=session['username'])

@app.route('/login.html')
def lo():
	return render_template('login.html')
@app.route('/signup.html')
def si():
	return render_template('signup.html')
@app.route('/existing.html')
def ex():
	return render_template('existing.html')
@app.route('/new.html')
def new():
	return render_template('new.html')
@app.route('/table1.html')
def tb1():
	return render_template('table1.html')

@app.route('/index.html')
def osearch():
	return render_template('index.html')

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method=="POST":
         ## all user from the collection named users
        login_user = user.find_one({'username': request.form['username']})
        if login_user:
            pw_hash = login_user['password']
            #print(pw_hash)
            
            if (bcrypt.check_password_hash(pw_hash, request.form['pass'])): 
                session['username'] = request.form['username']
                # return redirect(url_for('index'))
                #invalid=0
                return redirect(url_for('home'))
            else:
                invalid=1
        else :
            invalid=2
    
   
        
    return render_template('login.html',invalid=invalid)
    



@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=="POST":
        
        existing_user = user.find_one({'username': request.form['username']})
        
        if existing_user is None:
            exi_user=0
            pw_hash = bcrypt.generate_password_hash(request.form['password'])
            user.insert_one({'username': request.form['username'] ,'email': request.form['email'] , 'password': pw_hash,'org':request.form['org']  })
            print('Account Created Sucessfully')
            session['username']=request.form['username']
            return redirect(url_for('home'))
        else:
            exi_user=1
            #return 'User Already exists'
    return render_template('signup.html', exi_user=exi_user)



    return


@app.route('/test')
def test():
    res=session['target']
    return f'Page of {res}'


@app.route('/newproject', methods=['POST','GET'])
def newproject():
	url=request.form['url']
	module=request.form['module']
	
	if module == 'crawler':
		tar=mongo.db.crawler.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('crawl'))
        
	elif module =='dns':
		tar=mongo.db.dns.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('dns'))
	elif module =='header':
		tar=mongo.db.header.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('header'))
	elif module =='whois':
		tar=mongo.db.whois.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('whois'))
	if module =='wayback':
		tar=mongo.db.wayback.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('wayback'))
	elif module =='ssl':
		tar=mongo.db.ss.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('ssl'))
	elif module == 'subdomain':
		tar=mongo.db.subdom.find_one({'target':url,'username':session['username']})
		if tar:
			alreadytarget=1
		else:
			alreadytarget=0
			session['target']=url
			return redirect(url_for('subdom'))

	return render_template('new.html',alreadytarget=alreadytarget)
    



  
@app.route('/logout')
def logout():
  session.clear()
  #session['logged_out']=1
  print('Session Cleared and Logged Out')
  return render_template('login.html')  











#crawler done
@app.route('/crawler')
def crawl():
    target = session['target']
    #ext = tldextract.extract(abc)
    #domain = ext.registered_domain
    output={}
    data ={}
    craw=mongo.db.crawler
    res=crawler(target,output,data)
    
    craw.insert_one(res)
    mod="Crawler"
    return render_template('table.html', data=res, target=target, module=mod)



#dns

@app.route('/dns')
def dns():
    abc = session['target']
    ext = tldextract.extract(abc)
    domain = ext.registered_domain
    output={}
    data ={}
    user=session['username']
    target=session['target']
    res= dnsrec(domain,output,data,target,user)
    dnsenum=mongo.db.dns
    
    
    dnsenum.insert_one(res)
    mod="DNS"
    return render_template('table.html', data=res, target=target, module=mod)


#headers
@app.route('/header')
def header():
    target = session['target']
    output={}
    data ={}
    user=session['username']
    
    res= headers(target, output, data,user)
    head=mongo.db.header
    head.insert_one(res)
    mod="Header"
    return render_template('table.html', data=res, target=target, module=mod)
#portscan
''''@app.route('/portscan', methods=['POST'])
def portscan():
    target = request.form['name']
    output={}
    data ={}
    return dnsrec(domain,output,data)'''
#sslinfo
@app.route('/ssl')
def ssl():
    target = session['target']
    ext = tldextract.extract(target)
    hostname = '.'.join(part for part in ext if part)
    output={}
    data={}
    sslp=443
    user=session['username']
    
    res =   cert(hostname, sslp, output, data, target,user)
    sslin=mongo.db.ssl
    
    
    sslin.insert_one(res)
    mod="SSL Information"
    return render_template('table.html', data=res, target=target, module=mod)
#subdom
@app.route('/subdom')
def subdom():
    target = session['target']
    user=session['username']
    ext = tldextract.extract(target)
    hostname = '.'.join(part for part in ext if part)
    domain = ext.registered_domain
    output = {}
    data = {}
    tout = 30
    conf_path = "C:\\Users\\vinay\\Videos\\blackhat1\\test\\conf"
    res = subdomains(hostname, tout, output, data, conf_path,user,target)
    sub = mongo.db.subdom
    sub.insert_one(res)
    mod ="Subdomain "
    return render_template('subtable.html', data=res, target=target, module=mod)
#wayback


@app.route('/wayback')
def wayback():
    target = session['target']
    output={}
    data={}
    user=session['username']
    res=  timetravel(target, output, data,user)
    way=mongo.db.wayback
    
    
    way.insert_one(res)
    mod="Way back"
    return render_template('table.html', data=res, target=target, module=mod)
    #return render_template('form_data.html', name=name, email=email)

#whois
@app.route('/whois')
def whois():
    target = session['target']
    
    output={}
    data ={}
    ext = tldextract.extract(target)
    hostname = '.'.join(part for part in ext if part)
    try:
        ipaddress.ip_address(hostname)
        ip=hostname
    except Exception:
        try:
              ip = socket.gethostbyname(hostname)
        except:
              return render_template('error.html')
    user=session['username']
    
    res = whois_lookup(ip, output, data,target,user)
    who=mongo.db.whois
    
    who.insert_one(res)
    mod="Whois Lookup"
    return render_template('table.html', data=res, target=target, module=mod)





@app.route('/submit')
def submit():
    module = request.args.get('module')
    if module == 'crawler':
    	collection=mongo.db.crawler
    elif module == 'dns':
    	collection=mongo.db.dns
    elif module == 'whois':
    	collection=mongo.db.whois
    elif module =='header':
    	collection = mongo.db.header
    elif module == 'ssl':
    	collection = mongo.db.ssl
    elif module == 'wayback':
    	collection = mongo.db.wayback
    elif module == 'subdomain':
    	collection = mongo.db.subdom

			
    res=collection.find({'username':session['username']},{'target':1,'_id':0})
    table=[]
    for cur in res:
    	table.append(cur)
    	#print(cur)
    print(table)
    return render_template('table3.html',data=table,mod=module)

@app.route('/view')
def view():
    target = request.args.get('target')
    module = request.args.get('module')
    if module == 'crawler':
    	collection=mongo.db.crawler
    elif module == 'dns':
    	collection=mongo.db.dns
    elif module == 'whois':
    	collection=mongo.db.whois
    elif module =='header':
    	collection = mongo.db.header
    elif module == 'ssl':
    	collection = mongo.db.ssl
    elif module == 'wayback':
    	collection = mongo.db.wayback
    elif module == 'subdomain':
    	collection = mongo.db.subdom

    
    res=collection.find({'target':target})
    table=[]
    for cur in res:
    	table.append(cur)
    #print(table)
    print(target)
    return render_template('table4.html',data=table)



if __name__ == '__main__':
    app.secret_key='secretivekey'
    app.run(debug=True)