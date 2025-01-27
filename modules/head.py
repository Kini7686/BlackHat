#!/usr/bin/env python3

import requests
#from modules.export import export
requests.packages.urllib3.disable_warnings()

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def headers(target, output, data,user):
	result = {}
	result["username"]=user
	result["target"]=target
	print(f'\n{Y}[!] Headers :{W}\n')
	try:
		rqst = requests.get(target, verify=False, timeout=10)
		for key, val in rqst.headers.items():
			print(f'{C}{key} : {W}{val}')
			if output != 'None':
				result.update({key: val})
	except Exception as e:
		print(f'\n{R}[-] {C}Exception : {W}{e}\n')
		if output != 'None':
			result.update({'Exception': str(e)})
	result.update({'exported': False})
	return result
