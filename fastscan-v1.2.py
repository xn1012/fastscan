#!/usr/bin/env python
#--*-- coding:utf-8 --*-- 
import portscan as ps
import fcntl
import json
import os 
import sys
import getopt
import multiprocessing
from threading import Thread, Lock
from Queue import Queue
import datetime
import time
from collections import OrderedDict, defaultdict
import codecs
import types
import socket
from itertools import chain

sub_num = multiprocessing.cpu_count()
dir0 = os.getcwd()
q = Queue()
glock = Lock()
file = None

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
    dic = OrderedDict()
    interval = (port_max - port_min) // num + 1
    threads = [ps.scanThread(ip, i * num, (i+1) * num) for i in xrange(interval)]
    map(lambda x:x.start(),threads)
    map(lambda x:x.join(),threads)
    res = [threads[i].getports() for i in xrange(interval)]
    results = list(chain(*res))
    return results



def Worker_helper(sfile, sub, port_max, port_min,num):
    subfile = sfile + '_' + str(sub)
    str0 = dir0 + '/input/' + subfile 
    dir1= dir0 + '/out1/'
    str1 = dir1 + subfile + "_open"
    log = dir1 + file + '.log'

    ip_ports = {}
    list1 =[]

    with open(str0, 'r')as f:
        for eachline in f:
            ip = eachline.strip()
            try:
                output = scan(ip, port_max, port_min,num)
            except Exception as e:
                print("error:{} occured at ip:{}".format(e, ip))
                with open(log, 'a') as flog:
                    fcntl.flock(flog.fileno(), fcntl.LOCK_EX)
                    flog.write("error: {} at ip:{} during scan\n".format(e, ip))
            else:
                ip_ports[ip] = []
                ip_ports[ip] = output
                list1.append(json.dumps(ip_ports) + '\n')
                ip_ports.clear()
                if len(list1) == 200:
                    with open(str1, 'a') as results1:
                        results1.writelines(list1)
                    list1 = []

    #print("subfile {}'s unknown domains num:{}".format(sub,len(list3)))
    if len(list1) != 0:
        with open(str1, 'a') as results1:
            results1.writelines(list1)


def GetIP(i, list1,list2, ip_dic):
    global q
    while True:
        domain = q.get()
        print("\n---domain left: {}---".format(q.qsize()))
        try:
            ip = socket.gethostbyname(domain)
            print("\nhost: {}'s ip is: {}".format(domain, str(ip)))
        except socket.error:
            print('\nhost: {} unknown!!!'.format(domain))
            glock.acquire()
            list2.append(domain + '\n')
            print("\nunknown num accumulated:{}".format(len(list2)))
            glock.release()
            continue
        else:
            glock.acquire()
            if ip_dic.has_key(ip):
                ip_dic[ip].append(domain)
            else:
                list1.append(ip + '\n')
                ip_dic[ip].append(domain)
                print("\n---accumulated IPs :{}---".format(len(list1)))
            glock.release()
        finally:
            q.task_done()



def get_ip(file):
    global q
    limit = 50
    str0 = dir0 + '/input/' + file
    str00 = dir0 + '/input/' + file + '_IPs'
    str1 = dir0 + '/out1/' + file + '_IP2Domain'
    str2 = dir0 + '/out1/' + file + "_unknown"
    log = dir0 + '/out1/' + file + '.log'
    ip_dic = defaultdict(list)
    list1 = []
    list2 = []

    n = 0
    with open(str0, 'r') as f0:
        for eachline in f0:
            domain = eachline.strip()
            q.put(domain)
            n = n + 1


    time_start = time.time()
    threads = [Thread(target=GetIP, args=(i, list1, list2, ip_dic)) for i in xrange(limit)]
    map(lambda x:x.setDaemon(True),threads)
    map(lambda x:x.start(),threads)
    q.join()
    time.sleep(5)
    time_end = time.time()
    cost = time_end - time_start
    print("\ntime: DNS query cost:{}".format(cost))
    print("\nfile: {}, Total Domains:{}, total IPs:{}, unknow Domains: {}".format(file, n, len(list1), len(list2)))

    with open(log, 'a') as flog:
        flog.write("time: DNS query cost:{} s\n".format(cost))
        flog.write("file:{}, Total Domains: {}, total IPs: {}, unknown Domains: {}\n".format(file, n, len(list1), len(list2)))

    print("\n----Saving the DNS query results now----")
    try:
        with open(str00, 'w') as f00:
            f00.writelines(list1)
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("error: {} at writing scan _IPs file\n".format(e))
        return False
    try:       
        with open(str2, 'w') as f2:
            f2.writelines(list2)
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("error: {} at writing _unknown file\n".format(e))
        return False

    list3 = []
    for key, value in ip_dic.items():
        rec = {}
        rec[key] = value
        list3.append(json.dumps(rec) + '\n')
    try:
        with open(str1, "w") as f1:
            f1.writelines(list3)
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("error:{}, when save _IP2Domain file\n".format(e))
        return False

    return True

def main(argv):
    global file
    
    if not os.path.exists('./out1/'):
        os.makedirs('./out1/')

    try:
        opts,args = getopt.getopt(argv, "-h-f:-x-i:-a:-n:", ["help","file=", "need to extract", "port_min=", "port_max=", "batch_num="])
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

    if not get_ip(file):
        print("\nExit: error when save:{}'s DNS query results to file".format(file))
        return
    
    str0 = dir0 + '/input/' + file + '_IPs'
    log = dir0 + '/out1/' + file + '.log'
    total_ips = splitfile(str0)

    #pool number default equal to cpu kernels and scan
    time_start = time.time()
    pool = multiprocessing.Pool(sub_num)
    for i in xrange(sub_num):
        pool.apply_async(Worker_helper, (file + '_IPs', i, port_max, port_min,num)) 
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

    with open(str1, 'w') as results1:
        for i in xrange(sub_num):
            try:
                with open(dir1 + file + '_IPs_' + str(i) + '_open','r') as f1:
                    content1 = f1.read()
                    results1.write(content1)
            except Exception as e:
                continue

    time_end = time.time()
    cost2 = time_end - time_start
    print("\nfile: {}, total IPs:{}".format(file, total_ips))
    print("\nPortScanV1.2: domain file:{},scan cost: {}, combine cost:{}".format(file,cost1,cost2))

    with open(log, 'a') as flog:
        flog.write("\nPortScanV1.2: file:{},IPs:{}, scan cost:{} s, combine cost:{}".format(file, total_ips, cost1, cost2))

    Clear_helper()


def Clear_helper():
    str0 = dir0 + '/input/' + file 
    str00 = str0 + '_IPs'
    dir1 = dir0 + '/out1/'

    # try:
    #     os.remove(str00)
    # except:
    #     pass

    for i in xrange(sub_num):
        subfile = str00 + '_' + str(i)
        str1 = dir1 + file + '_IPs_' + str(i) + '_open'

        try:
            os.remove(str1)
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


