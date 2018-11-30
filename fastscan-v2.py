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
glock = Lock()
glock2 = Lock()
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

    interval = (port_max - port_min) // num + 1
    threads = [ps.scanThread(ip, i * num, (i+1) * num) for i in xrange(interval)]
    map(lambda x:x.start(),threads)
    map(lambda x:x.join(),threads)
    res = [threads[i].getports() for i in xrange(interval)]
    results = list(chain(*res))
    return results



def Worker_helper(sfile, sub, port_max, port_min,num):
    ssfile = sfile + '_' + str(sub)
    str0 = dir0 + '/input/' + ssfile 
    dir1 = dir0 + '/out2/'
    str1 = dir1+ ssfile + "_open"
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
                if len(list1) == 100:
                    with open(str1, 'a') as results1:
                        results1.writelines(list1)
                    list1 = []

    if len(list1) != 0:
        with open(str1, 'a') as results1:
            results1.writelines(list1)



def GetIP(i, list1, list2, new, ip_dic, q):
    global glock, glock2
    while True:
        domain = q.get()
        print("\n-----domain left: {}-----".format(q.qsize()))
        try:
            ip = socket.gethostbyname(domain)
            print("\nhost: {}'s ip is: {}".format(domain, ip))
        except socket.error:
            print('\nhost: {} unknown!!!'.format(domain))
            glock2.acquire()
            list2.append(domain + '\n')
            print("\nunknown num accumulated:{}".format(len(list2)))
            glock2.release()
            continue
        else:
            glock.acquire()
            if ip_dic.has_key(ip):
                ip_dic[ip].append(domain)
            else:
                list1.append(ip + '\n')
                new.append(ip + '\n')
                ip_dic[ip].append(domain)
                print("\n-----accumulated IPs :{}, batch IPs:{}-----".format(len(list1), len(new)))
            glock.release()
        finally:
            q.task_done()


def get_ip(sub, list1, list2, new, ip_dic):
    q = Queue()
    limit = 20
    str0 = dir0 + '/input/' + file + '_' + str(sub)
    str00 = dir0 + '/input/' + file + '_' + str(sub) +'_IPs'
    log = dir0 + '/out2/' + file + '.log'
    
    n = 0
    with open(str0, 'r') as f0:
        for eachline in f0:
            domain = eachline.strip()
            q.put(domain)
            n = n + 1
    
    print("\nBatch {}: {} domains queued, q size: {}, list1: {}, new:{}".format(sub, n, q.qsize(), len(list1), len(new)))

    time_start = time.time()
    threads = [Thread(target=GetIP, args=(i, list1, list2, new, ip_dic, q)) for i in xrange(limit)]
    map(lambda x:x.setDaemon(True),threads)
    map(lambda x:x.start(),threads)
    q.join()
    time.sleep(10)
    time_end = time.time()
    cost = time_end - time_start
    print("\nBatch:{} DNS query time cost:{} s".format(sub, cost))

    try:
        with open(str00, 'w') as f00:
            f00.writelines(new)
        print("\nBatch: {} have:{} domains, {} new IPs to scan,  accu IPs: {}, accu unknown:{}".format(sub, n, len(new), len(list1), len(list2)))
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("Batch:{} DNS query time cost:{} s\n".format(sub, cost))
            flog.write("error: batch {} new scan ip file write error\n".format(sub))           
        return False

    with open(log, 'a') as flog:
        flog.write("Batch:{} DNS query time cost:{} s\n".format(sub, cost))
        flog.write("Batch:{} have: {} domains, {} new IPs to scan, accu IPs: {}, accu unknown:{}\n".format(sub, n, len(new), len(list1), len(list2)))
    return True

def main(argv):
    global file
    if not os.path.exists('./out2/'):
        os.makedirs('./out2/')

    try:
        opts,args = getopt.getopt(argv, "-h-f:-x-i:-a:-n:", ["help","file=", "need to extract", "port_min=", "port_max=", "[batch_num="])
    except getopt.GetoptError:
        print("fastscan-v2.py -f <inputfile> -x (whois result file need to extract) -i <min port> -a <max port> -n <batch number> ")
        sys.exit()

    for opt_name,opt_value in opts:
        if opt_name in ('-h','--help'):
            print("fastscan-v2.py -f <inputfile>  -x(whois result file need to extract) -i <min port> -a <max port> -n <batch number>")
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
            print("fastscan-v2.py -f <inputfile> -x (whois result file need to extract) -i <min port> -a <max port> -n <batch number>")   

    
    str0 = dir0 + '/input/' + file
    dir1 = dir0 + '/out2/' 
    log = dir1 + file + '.log'
    total_domain= splitfile(str0)

    time_start = time.time()
    ip_dic = defaultdict(list)
    list1 = []
    list2 = []   
    new = []
    for i in xrange(sub_num):
        new[:] = []
        if not get_ip(i, list1, list2, new, ip_dic):
            continue

        str00 = dir0 + '/input/' + file + '_' + str(i) + '_IPs'
        sfile = file + '_' + str(i) + '_IPs'
        batch_IPs = splitfile(str00) 

        #pool number default equal to cpu kernels and scan
        time_starti = time.time()
        pool = multiprocessing.Pool(sub_num)
        for j in xrange(sub_num):
            pool.apply_async(Worker_helper, (sfile, j, port_max, port_min,num)) 
        pool.close()
        pool.join()
        time.sleep(5)

        str1 = dir1 + sfile + '_open'
        with open(str1, 'w') as results1:
            for k in xrange(sub_num):
                try:
                    with open(dir1 + sfile + '_' + str(k) + '_open','r') as f1:
                        content1 = f1.read()
                        results1.write(content1)
                    os.remove(dir1 + sfile + '_' + str(k) + '_open')
                except Exception as e:
                    continue
        
        time_endi = time.time()
        costi = time_endi - time_starti
        with open(log, 'a') as flog:
            flog.write("Batch:{} scan port: {}-{} time cost:{} s \n".format(i, port_min, port_max, costi))  


    #save list1, list2，ip_dic
    str3 = dir1 + file + '_IP2Domain'
    str2 = dir1 + file + '_unknown'
    str1 = str0 + '_IPs'
    
    list3 = []
    for key, value in ip_dic.items():
        rec = {}
        rec[key] = value
        list3.append(json.dumps(rec) + '\n')   
    try:
        with open(str3, 'w') as f3:
            f3.writelines(list3)
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("error: {} at writing _IP2Domain file\n".format(e))  
    try:
        with open(str2, 'w') as f2:
            f2.writelines(list2)
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("error: {} at writing _unknown file\n".format(e))
    try:
        with open(str1, 'w') as f1:
            f1.writelines(list1)
    except Exception as e:
        with open(log, 'a') as flog:
            flog.write("error: {} at writing _IPs file\n".format(e))
    
    #combine open ports files
    str4 = dir1 + file + '_open'
    with open(str4, 'w') as f4:
        for i in xrange(sub_num):
            sfile = file + '_' + str(i) + '_IPs'
            str5 = dir1 + sfile + '_open'
            try:
                with open(str5, 'r') as fsub:
                    content = fsub.read()
                    f4.write(content)
            except Exception as e:
                pass
    
    time_end = time.time()
    cost1 = time_end - time_start
    print("PortScanV2.0: file: {}, Total domains:{}, IPs:{}, unknow: {}, Total Time: {} s\n".format(file, total_domain, len(list1),len(list2), cost1))
    with open(log, 'a') as flog:
        flog.write("PortScanV2.0: file:{},Total domains:{}, IPs:{}, unknow: {}, Total Time:{} s\n".format(file, total_domain, len(list1),len(list2), cost1))

    Clear_helper()


def Clear_helper():
    str0 = dir0 + '/input/' + file 
    dir1 = dir0 + '/out2/'

    for i in xrange(sub_num):
        subfile1 = str0 + '_' + str(i)
        subfile2 = subfile1 + '_IPs'
        str1 = dir1 + file + '_' + str(i)+ '_IPs_open'
        try:
            os.remove(str1)
        except:
            pass
        try:
            os.remove(subfile1)
        except:
            pass
        try:
            os.remove(subfile2)
            for j in xrange(sub_num):
                os.remove(subfile2 + '_' + str(j))
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


