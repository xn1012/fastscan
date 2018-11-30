#!/usr/bin/env python
#--*-- coding:utf-8 --*--  

import time
import socket
from threading import Thread
from Queue import Queue
import platform


# 端口扫描工具
class scanThread(Thread):
	def __init__(self, ip, port_min=0, port_max=65535):
		Thread.__init__(self)
		assert isinstance(port_max, int) and isinstance(port_min, int)
		self.ip = ip
		self.port_min = max(0, port_min)
		self.port_max = min(65535, port_max)
		self.open_ports = []

	# 重写run
	def run(self):
		return self.__checker()
	# 检测
	def __checker(self):
		for port in range(self.port_min, self.port_max):
			flag = self.__connect(port)
			if flag:
				self.open_ports.append(port)

	def getports(self):
		Thread.join(self)
		return self.open_ports

	# 连接,default to ipv4, tcp
	def __connect(self, port):
		socket.setdefaulttimeout(1)
		s = socket.socket()

		curr_os = platform.system()
		if curr_os == 'Windows':
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		else:
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

		try:
			t_start = time.time()
			ret = s.connect_ex((self.ip, port))
			t_end = time.time()
			if ret == 0:
				flag = True
			else:
				flag = False
		except:
			flag = False
		s.close()
		if flag:
			connect_time = str(int((t_end - t_start) * 1000))
			info = 'Find --> [IP]: %s, [PORT]: %s, [Connect Time]: %s ms' % (self.ip, port, connect_time)
			print(info)
		return flag



