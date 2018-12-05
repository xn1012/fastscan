#!/usr/bin/env python
#--*-- coding:utf-8 --*-- 

import json
import os
import sys
import getopt

dir0 = os.getcwd()
port_flag = False
dom_flag = False
file = None
num = 1000

def main(argv):
	global file,num
	try:
		opts,args = getopt.getopt(argv, "-h-f:-n:", ["help","file=", "num="])
	except getopt.GetoptError:
		print("extract.py -f <inputfile> -n <num> to extract suspicious IPs from [port]/[domain] if >= num, defaults:1000")
		sys.exit()

	for opt_name,opt_value in opts:
		if opt_name in ('-h','--help'):
			print("extract.py -f <inputfile> -n <num> to extract suspicious IPs from [ports]/[domain] if >= num, defaults:1000")
			sys.exit()
		elif opt_name in ('-f','--file'):
			file = opt_value
		elif opt_name in ('-n','--num'):
			num = int(opt_value)      
		else:
			print("extract.py -f <inputfile> -n <num> to extract suspicious IPs from [ports]/[domain] if >= num, defaults:1000")   

	result1 = []
	result2 = []
	str0 = dir0 + '/' + file
	with open(str0, 'r') as f0:
		for line in f0:
			rec = json.loads(line.strip())
			for key, value in rec.items():
				ip = key
				cnt = len(value)
				if cnt > num :
					result1.append(line)
					result2.append(ip + '\t' + str(cnt) + '\n')


	str1 = dir0 + '/' +  'sus_' + file
	with open(str1, 'w') as f1:
		f1.writelines(result1)
	str2 = dir0 + '/' +  'sus_sta_' + file
	with open(str2, 'w') as f2:
		f2.writelines(result2)



if __name__ == '__main__':
	main(sys.argv[1:])