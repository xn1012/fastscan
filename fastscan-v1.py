#!/usr/bin/env python
#--*-- coding:utf-8 --*-- 
import portscan as ps
import json
import os 
import sys
import getopt
import multiprocessing
from Queue import Queue
import datetime
import time
import collections
import socket
from itertools import chain

sub_num = multiprocessing.cpu_count()
dir0 = os.getcwd()



def mksubfile(lines, sfile, sub):
    dfile  = sfile + '_' + str(sub)
    print( "make sub file:{}".format(sub))
    with open(dfile, 'w') as fout:
        fout.writelines(lines)
    sub = sub + 1
    return sub


def splitfile(file):
    print("\n splitting the file now ...")

    time_start = time.time()
    with open(file, 'r') as f0:
        for i, line in enumerate(f0):
            pass
    line_cnt = i + 1

    line_size = line_cnt / sub_num
    print("\n Total lines cnt: {}".format(line_cnt))

    sub = 0
    lines = []
    with open(file, 'r') as f0:
        for eachline in f0: 
            if len(lines) == line_size:
                if sub + 1 < int(sub_num):
                    sub = mksubfile(lines, file, sub)
                    lines = []
            else:
                pass
            lines.append(eachline)

        if len(lines) != 0:
            mksubfile(lines, file,sub)
        time_end = time.time()
        cost = time_end - time_start
        print("\n Split Done , cost {}".format(cost))

    return line_cnt

def scan(ip, port_max, port_min,num):
    dic = collections.OrderedDict()
    interval = (port_max - port_min) // num + 1
    threads = [ps.scanThread(ip, i * num, (i+1) * num) for i in xrange(interval)]
    map(lambda x:x.start(),threads)
    map(lambda x:x.join(),threads)
    res = [threads[i].getports() for i in xrange(interval)]
    results = list(chain(*res))
    dic["ip"] = str(ip)
    dic["open"] = results
    return dic


def Worker_helper(file,sub, port_max, port_min,num):
    subfile = file + '_' + str(sub)
    str0 = dir0 + '/input/' + subfile 
    directory = dir0 + '/out1/'
    str1 = directory + subfile + "_open"
    str3 = directory + subfile + "_unknown"
    domains = {}
    fail_list = []
    list1 =[]
    list3 =[]

    with open(str0, 'r')as f:
        for eachline in f:
            domain = eachline.strip()
            output = collections.OrderedDict()
       
            try:
                ip = socket.gethostbyname(domain)
                print("server: {}'s ip is: {}".format(domain,str(ip)))
            except socket.error:
                print('hostname {} unknown!!!'.format(domain))
                list3.append(domain + '\n')
                continue
            try:
                output = scan(ip, port_max, port_min,num)
            except Exception as e:
                print("error:{} occured at domain:{}".format(e, domain))

            else:
                domains[domain]=collections.OrderedDict()
                domains[domain]=output
                list1.append(json.dumps(domains) + '\n')
                domains.clear()
                if len(list1) == 200:
                    with open(str1, 'a') as results1:
                        results1.writelines(list1)
                    list1 = []
	               

    if len(list1) != 0:
        with open(str1, 'a') as results1:
            results1.writelines(list1)
    #print("subfile {}'s unknown domains num:{}".format(sub,len(list3)))
    if len(list3) != 0:
        with open(str3, 'w') as results3:
            results3.writelines(list3)
    

def main(argv):
    file = None
    try:
        opts,args = getopt.getopt(argv, "-h-f:-x-i:-a:-n:", ["help","file=", "need to extract", "port_min=", "port_max=", "[batch_num="])
    except getopt.GetoptError:
        print("test.py -f <inputfile> -x <whois result file need to extract> -i <min port> -a <max port> -n <batch number> ")
        sys.exit()

    for opt_name,opt_value in opts:
        if opt_name in ('-h','--help'):
            print("test.py -f <inputfile>  -x <whois result file need to extract> -i <min port> -a <max port> -n <batch number>")
            sys.exit()
        elif opt_name in ('-f','--file'):
            file = opt_value
        elif  opt_name in ('-x','--extract'):
            domainfile = Extract_domain(file)
            file = domainfile
        elif opt_name in ('-i', '--port_min'):
        	port_min = int(opt_value)
        elif opt_name in('-a', '--port_max'):
        	port_max = int(opt_value)
        elif opt_name in('-n', '--batch_num'):
            num = int(opt_value)
        else:
            print("test.py -f <inputfile> -x <whois result file need to extract> -i <min port> -a <max port> -n <batch number>")

    str0 = dir0 + '/input/' + file
    total_lines = splitfile(str0)

    if not os.path.exists('./out1/'):
        os.makedirs('./out1/')

    #pool number default equal to cpu kernels and scan
    time_start = time.time()
    pool = multiprocessing.Pool(sub_num)
    for i in xrange(sub_num):
        pool.apply_async(Worker_helper, (file,i,port_max, port_min,num)) 
    pool.close()
    pool.join()
    time.sleep(5)

    time_end = time.time()
    cost1 = time_end - time_start

    print("\n-----combining the results now...-----")
    time_start = time.time()
    timestamp = datetime.datetime.now().strftime('%m%d')
    dir1 = dir0 + '/out1/' 
    str1 = dir1 + file + '_open'
    str3 = dir1 + file + '_unknown'

    #if file < 300M, combining the succeed results
    with open(str1 + '_' + timestamp, 'w') as results1:
        for i in xrange(sub_num):
            try:
                with open(dir1 + file + '_' + str(i) + '_open','r') as f1:
                    content1 = f1.read()
                    results1.write(content1)
            except Exception as e:
                continue

    with open(str3 + '_' + timestamp, 'w') as results3:
        for i in xrange(sub_num):
            try:
                with open(dir1 + file + '_' + str(i) + '_unknown','r') as f3:
                    content3 = f3.read()
                    results3.write(content3)
            except Exception as e:
                continue

    time_end = time.time()
    cost2 = time_end - time_start
    print("\nfile: {}, Total lines:{}".format(file, total_lines))
    print("\nPortScanV2:domain file:{},scan cost: {}, combine cost:{}".format(file,cost1,cost2))
    Clear_helper(file)


def Clear_helper(file):
    str0 = dir0 + '/input/' + file 
    dir1 = dir0 + '/out1/'

    for i in xrange(sub_num):
        subfile = str0 + '_' + str(i)
        str1 = dir1 + file + '_' + str(i) + '_open'
        str3 = dir1 + file + '_' + str(i) + '_unknown'

        if True:
            try:
                os.remove(str1)
            except:
                pass
        try:
            os.remove(str3)
        except:
            pass
        try:
            os.remove(subfile)
        except:
            pass

    print("\nclear work have done!")


#the input file is whois result files ,extract the domains
def Extract_domain(file):
    str0 = dir0 + '/input/' + file
    domains=[]

    with open(str0, 'r') as f0:
        for eachline in f0:
            record = json.loads(eachline.strip())
            for key in record.keys():
                domains.append(key + '\n')
    str1 = dir0 + '/input/' + file + '_domains'   
    with open(str1, 'w') as fout:
        fout.writelines(domains)
    return file + '_domains'  


if __name__ == '__main__':
	main(sys.argv[1:])


