#!/usr/bin/env python
#--*-- coding:utf-8 --*-- 

import json
import os
import sys
import getopt
import datx
reload(sys)
sys.setdefaultencoding('utf-8')

dir0 = os.getcwd()
file = None
NUM = 1000

def main(argv):
	global file
	try:
		opts,args = getopt.getopt(argv, "-h-f:", ["help","file="])
	except getopt.GetoptError:
		print("extract-loc.py -f <inputfile> to extract suspicious IPs from [port] or [domain] numbers, locate IPS")
		sys.exit()

	for opt_name,opt_value in opts:
		if opt_name in ('-h','--help'):
			print("extract-loc.py -f <inputfile> to extract suspicious IPs from [ports] or [domain] numbers locate IPS")
			sys.exit()
		elif opt_name in ('-f','--file'):
			file = opt_value        
		else:
			print("extract-loc.py -f <inputfile> to extract suspicious IPs from [ports] or [domain] numbers locate IPS")  

	result1 = []
	result2 = []
	str0 = dir0 + '/' + file

	dbase = datx.City(dir0 + '/IPQuery/' + 'mydata4vipday3.datx')

	with open(str0, 'r') as f0:
		for line in f0:
			rec = json.loads(line.strip())
			for key, value in rec.items():
				ip = key
				cnt = len(value)
				if cnt > NUM :
					res = dbase.find(ip)
					result1.append(line)
					result2.append(ip + '\t' + str(cnt) + '\t' + res[0] + '\t' + res[1] + '\t' + res[2] + '\t' + res[3] + '\t' + res[4] + '\t'+ res[13] + '\n')


	str1 = dir0 + '/' +  'sus_' + file
	with open(str1, 'w') as f1:
		f1.writelines(result1)

	str2 = dir0 + '/' +  'sus_loc_' + file
	with open(str2, 'w') as f2:
		f2.writelines(result2)



if __name__ == '__main__':
	main(sys.argv[1:])