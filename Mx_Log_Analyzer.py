#!/usr/bin/env python
#Author : Manindra T
#Date : 25th-May-2016
import os, subprocess, sys
import time, re, json
from pprint import pprint
import argparse

if len(sys.argv) < 2:
	try:
                import logging
	except Exception, e:
		print "Installing modules logging.."
		os.system("easy_install -U logging")
		import logging
if len(sys.argv) > 3:
	try:
		import paramiko, logging, requests
	except Exception, e:
		print ("Installing paramiko")
		os.system("wget -P /tmp --no-check-certificate https://bootstrap.pypa.io/get-pip.py")
		time.sleep(10)
		os.system("python2.6 /tmp/get-pip.py && rm -rf /tmp/get-pip.py")
		os.system("yum install -y gcc glic libffi-devel python-devel openssl-devel pycrypto && pip install -U cryptography paramiko==1.15.3 logging requests")
		import paramiko, logging, requests

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--mgmtip", action="store", dest="mgmt_ip", required=False, help="Enter maxta mgmt ip")
parser.add_argument("-v", "--vcip", action="store", dest="vc_ip", required=False, help="Enter vCenter ip")
parser.add_argument("-u", "--vcuser", action="store", dest="vc_user", required=False, help="Enter vCenter username")
parser.add_argument("-p", "--vcpwd", action="store", dest="vc_pwd", required=False, help="Enter vCenter password")

args = parser.parse_args()

# Code for SSH and SCP Session establishment
#============================================================================================================

def createSshClient(server, username, password, portnum=''):
	#Setup SSH client
	logger.info("createSshClient server='%s' port='%s'", server, portnum)
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		if portnum=='':
			ssh.connect(server, username=username, password=password)
		else:
			logger.info("SpecialCase: server='%s' port='%s'", server, portnum)
			ssh.connect(server, port=portnum, username=username, password=password)

	except Exception, e:
		logger.error("Unable to connect to %s. Please check credentials.", server)
		raise Exception("Unable to connect to " + server +\
					". Please check credentials.")

	logger.info("createSshClient server='%s' returns to the caller.", server)
	return ssh


def createScpClient(server, username, password):
	#Setup SCP client
	logger.info("createScpClient server='%s'", server)

	transport = paramiko.Transport(server)
	transport.connect(username=username,
					  password=password)
	scp = paramiko.SFTPClient.from_transport(transport)
	logger.info("createScpClient server='%s' returns to the caller.", server)
	return scp


def executeRemote(sshchannel, cmd, strict = True):
	logger.info("%s: Executing '%s'",
				sshchannel.get_transport().getpeername()[0], cmd)
	stdin, stdout, stderr = sshchannel.exec_command(cmd)   
	retstdout = []
	retstderr = []
	for line in stdout:
		logger.info('stdout:' + line.strip('\n'))
		retstdout.append(line.strip('\n'))

	for line in stderr:
		logger.error('stderr:' + line.strip('\n'))
		retstderr.append(line.strip('\n'))

	while True:
		if stdout.channel.exit_status_ready():
			break
		try:
			printMsg = stdout.channel.recv(1024)
			printMsg = printMsg.strip()
			if len(printMsg) > 0:
				logger.info('\t' + sshchannel.get_transport().getpeername()[0] +\
						' : ' +  printMsg)
		except Exception, e:
			pass

	exitCode = stdout.channel.recv_exit_status()
	logger.debug('%s : Executing %s returned %d',
			sshchannel.get_transport().getpeername()[0], cmd, exitCode)

	if exitCode != 0 and strict:
		for line in stderr:
			logger.error('\t' + sshchannel.get_transport().getpeername()[0] +\
					' : ' + line.strip('\n'))
			msg = sshchannel.get_transport().getpeername()[0] +\
					' : ' + line.strip('\n')
		exitprog(msg, -1)

	return (exitCode, retstdout, retstderr)

def copyToRemote (client, source, destination):
	#Copy file from local to the remote server.   
	logger.info("Copying '%s' to '%s':'%s'", source,
			client.get_channel().getpeername()[0], destination)
	client.put(source, destination)


def copyFromRemote (client, source, destination):
	#Copy from remote server to local
	logger.info("Copying '%s' to '%s'", source, destination)
	client.get(source, destination)


def remote_ssh_cmd(cmd,mgmtip_port,mgmtuser,mgmtpw):
	logger.info("Initialize SSH client to Server '%s' ...", mgmtip_port)

	if ':' in mgmtip_port:
		vdlist = mgmtip_port.split(':')
		mgmtip = vdlist[0]
		portnum = vdlist[1]
		logger.info("MgmtIP='%s' MgmtPort='%s'", mgmtip, portnum)
		sshclient = createSshClient(mgmtip, mgmtuser, mgmtpw, portnum)
	else:
		mgmtip = mgmtip_port
		logger.info("MgmtIP='%s'", mgmtip)
		sshclient = createSshClient(mgmtip, mgmtuser, mgmtpw)
	
	(rc, outdata, stderr) = executeRemote(sshclient, cmd, False)
	#logger.info("ret stdout '%s'", outdata)
	return (outdata, rc)
	if rc != 0 and rc != None:
		msg = "FAIL: cmd '%s' returns retcode %d." % (cmd, rc)
		exitprog(msg, -1)
	
	sshclient.close()
	logger.info("Just Closed Mgmt SSH Clients.")

def scp_file(mgmtip_port,mgmtuser,mgmtpw,source,destination,copyType):
	logger.info("Initialize SCP client to Server '%s' ...", mgmtip_port)
	scpclient = createScpClient(mgmtip_port, mgmtuser, mgmtpw)

	if copyType == 'put':        
		copyToRemote(scpclient, source, destination)
		time.sleep(10)
		logger.info("Succesfully copied file to destination")
		scpclient.close()
		logger.info("Just Closed Mgmt SCP Clients.")
	elif copyType == 'get':
		copyFromRemote (scpclient, source, destination)
		time.sleep(10)
		logger.info("Succesfully copied file from destination")
		scpclient.close()
		logger.info("Just Closed Mgmt SCP Clients.")
	else:
		logger.error("\n\nPlease specify copyType as put/get")
		
	

# Code for Logging
#===================================================================================================================	
def setup_logger(logger_name, log_file, level=logging.DEBUG):
	l = logging.getLogger(logger_name)
	formatter = logging.Formatter('%(message)s')
	fileHandler = logging.FileHandler(log_file, mode='w')
	fileHandler.setFormatter(formatter)
	streamHandler = logging.StreamHandler()
	streamHandler.setLevel(logging.INFO)
	streamHandler.setFormatter(formatter)
	l.setLevel(level)
	l.addHandler(fileHandler)
	l.addHandler(streamHandler)    

#====================================================================================================================
setup_logger('logger', 'ssh_con.log')
setup_logger('analyzer', 'maxta_log_analyzer.log')
setup_logger('analyzer_detail', 'maxta_log_analyzer_detail.log')
logger = logging.getLogger('logger')
logger1 = logging.getLogger('analyzer')   
logger2 = logging.getLogger('analyzer_detail')   
username = "root"
password = "Sierr@4all"  

def host_list():
	if len(sys.argv) < 2:
		nodes = []
		cmd = "zklist -c | tail -n+2 | awk '{print $3}' | cut -c 4-"
		p = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out1 = p.communicate()[0]
		out2 = out1.split(",\n")
		for i in out2[:-1]:
			nodes.append(i)
		nodes = sorted(nodes)
		logger1.info("List of nodes to be analyzed: %s\n" %nodes)
		logger2.info("List of nodes to be analyzed: %s\n" %nodes)
		return nodes

	else:	
		mgmtip = args.mgmt_ip
		vc_ip = args.vc_ip
		vc_user = args.vc_user
		vc_pwd = args.vc_pwd
		# Creating a session
		s = requests.session()
		login_url = 'http://%s/j_spring_security_check' %mgmtip
		logout_url = 'http://%s/j_spring_security_logout' %mgmtip
		spool_info = 'http://%s/api/v3/maxta/StoragePoolInfo' %mgmtip

		# Login to maxta mgmt server
		login_payload = {'j_vcenter': vc_ip, 'j_username': vc_user, 'j_password': vc_pwd}
		login = s.post(login_url, data=login_payload)

		# Get node info from the cluster
		nodes = []
		r = s.get(spool_info)
		string = r.content
		dict = json.loads(string)
		host_len =  len(dict['data'])
		for i in range(host_len):
			node = dict['data'][i]['ipAddr']
			node = str(node)
			nodes.append(node)
		nodes = sorted(nodes)

		# Logout session
		s.post(logout_url)

		logger1.info("List of nodes to be analyzed: %s\n" %nodes)	
		logger2.info("List of nodes to be analyzed: %s\n" %nodes)	
		return nodes

def get_interface():
		cmd = "ifconfig | grep -iE 'mtu'| grep -v lo | awk '{print $1}'"
		p = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out1 = p.communicate()[0]
		out2 = out1.split(":\n")
		return out2[1]

def set_ip():
	x = hosts[0]
	y = x.split('.') 
	y[-1] = str(55)
	ip = ".".join(y)
	interface = get_interface()
	ipaddr = "ifconfig %s %s netmask 255.255.255.0" %(interface,ip)
	logger.info("IpAddress %s is set to interface %s" %(ip,interface))
	os.system(ipaddr)

def run_cmd(ip,cmd):
	mycmd = "runuser -l tomcat -c 'quorumHelper -t %s -e \"%s\"'" %(ip,cmd)
	p = subprocess.Popen(mycmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out = p.communicate()[0]
	rc = p.returncode
	return out, rc

msg1 = "cat /var/log/maxta/mfsd.log* | grep -iE '=== MFS' | tail -n+2"
msg2 = "cat /var/log/maxta/mfsd.log* | grep -iE 'Assertion'"
msg3 = "cat /var/log/maxta/mfsd.log* | grep -iE 'Out of buffers'"
msg4 = "cat /var/log/messages* | grep -iE 'Out of memory'"
msg5 = "ls -l /etc/maxta/dumpDrive/ /root / | grep -iE '*core*|crash'"
msg6 = "touch /maxta/testfile.txt && sleep 5 && ls /maxta/testfile.txt && rm -rf /maxta/testfile.txt"
msg7 = "zklist -o -r | grep -iE 'OFFLINE'"
msg8 = "zklist -o -r | grep -iE 'MISSING'"
msg9 = "zklist -o -r | grep -iE 'FAILED'"
msg10 = "cat /var/log/messages* | grep -iE 'MFS: Startup procedure failed. Attempting restart.'"
msg11 = "df -h | head -n 2 | grep -iE '/'"
msg12 = "cat /var/log/maxta/mfsd.log | grep -iE 'MEMORY POOL ALLOCATION FAILURE'"
msg13 = "cat /var/log/maxta/mfsd.log | grep -iE 'zookeeper timeout'"
msg14 = "mxsplash.sh"
err_msgs = [msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10, msg11, msg12, msg13, msg14]

hosts = host_list()

if len(sys.argv) > 3:	
	set_ip()
	for ip in hosts:
		def ping():	
			platform = sys.platform
			if platform == 'linux2':    
				cmd = "ping -c 1 "+ip
				p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				out = p.communicate()[0]
				out = out.lower()
				if re.search('ttl=64', out):
					return 0
				else:
					return 1
			elif platform == 'win32':
				cmd = "ping -n 1 "+ip
				p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				out = p.communicate()[0]
				out = out.lower()
				if re.search('ttl=64', out):
					return 0
				else:
					return 1
			else:
				logger1.error("Platform unknown...")
				logger2.error("Platform unknown...")

		ping_status = ping()
		while ping_status != 0:
			print "waiting 120 secs"
			time.sleep(120)
			ping_status = ping()
		else:
			logger.info(ip+" is reachable\n")
			logger1.info("Executing check list commands on %s:" %ip)
			logger2.info("Executing check list commands on %s:" %ip)
			logger1.info("################################################\n")
			logger2.info("################################################\n")
			for cmd in err_msgs:
				logger1.info("Executing %s: \n" %(cmd))
				logger2.info("Executing %s: \n" %(cmd))
				(out,rc) = remote_ssh_cmd(cmd,ip,username,password)
				if cmd == msg1:
					for i in out:
						logger2.info(i)
					logger2.info("="*100)
					logger1.info("Please check the console or 'maxta_log_analyzer_detail.log' for mfsd restart info")
					logger1.info("="*100)
				elif cmd == msg6 and rc == 1:                                
					count = 0
					while rc == 1 and count <= 3:
						(out,rc) = remote_ssh_cmd(cmd,ip,username,password)                                        
						if rc != 1:
							for i in out:
								logger1.info(i)                                                        
								logger2.info(i)                                                        
								break
						count += 1
						time.sleep(10)
					logger1.info("="*100)
					logger2.info("="*100)
				elif cmd == msg11:
					for i in out:
						logger2.info(i)				
					logger2.info("="*100)
					logger1.info("Please check the console or 'maxta_log_analyzer_detail.log' file for system capacity utilization")
					logger1.info("="*100)
				elif cmd == msg14:
					for i in out:
						logger2.info(i)				
					logger2.info("="*100)
					logger1.info("Please check the console or 'maxta_log_analyzer_detail.log' file for mxsplash output")
					logger1.info("="*100)
				else:
					time.sleep(5)
					for i in out:
						logger1.info(i)
						logger2.info(i)
					logger1.info("="*100)
					logger2.info("="*100)
else:
	for ip in hosts:
		def ping():	
			platform = sys.platform
			if platform == 'linux2':    
				cmd = "ping -c 1 "+ip
				p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				out = p.communicate()[0]
				out = out.lower()
				if re.search('ttl=64', out):
					return 0
				else:
					return 1
			elif platform == 'win32':
				cmd = "ping -n 1 "+ip
				p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				out = p.communicate()[0]
				out = out.lower()
				if re.search('ttl=64', out):
					return 0
				else:
					return 1
			else:
				logger1.error("Platform unknown...")
				logger2.error("Platform unknown...")

		ping_status = ping()
		while ping_status != 0:
			print "waiting 120 secs"
			time.sleep(120)
			ping_status = ping()
		else:
			logger.info(ip+" is reachable\n")
			logger1.info("Executing check list commands on %s:" %ip)
			logger2.info("Executing check list commands on %s:" %ip)
			logger1.info("################################################\n")
			logger2.info("################################################\n")
			for cmd in err_msgs:
				logger1.info("Executing %s: \n" %(cmd))
				logger2.info("Executing %s: \n" %(cmd))
				(out,rc) = run_cmd(ip,cmd)
				if cmd == msg1:
					logger2.info(out)
					logger2.info("="*100)
					logger1.info("Please check the console or 'maxta_log_analyzer_detail.log' for mfsd restart info")
					logger1.info("="*100)
				elif cmd == msg6 and rc == 0:                                
					count = 0
					while rc == 0 and count <= 3:
						(out,rc) = run_cmd(ip,cmd)                                        
						if rc != 0:
							logger1.info(out)                                                        
							logger2.info(out)                                                        
							break
						count += 1
						time.sleep(10)
					logger1.info("="*100)
					logger2.info("="*100)
				elif cmd == msg11:
					logger2.info(out)				
					logger2.info("="*100)
					logger1.info("Please check the console or 'maxta_log_analyzer_detail.log' file for system capacity utilization")
					logger1.info("="*100)
				elif cmd == msg14:
					logger2.info(out)				
					logger2.info("="*100)
					logger1.info("Please check the console or 'maxta_log_analyzer_detail.log' file for mxsplash output")
					logger1.info("="*100)
				else:
					time.sleep(5)
					logger1.info(out)
					logger2.info(out)
					logger1.info("="*100)
					logger2.info("="*100)
