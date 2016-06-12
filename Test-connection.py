#!/usr/bin/python
import sys, re, os, getpass, argparse, subprocess
from pysphere import MORTypes, VIServer, VITask, VIProperty, VIMor, VIException, VIApiException
from pysphere.vi_virtual_machine import VIVirtualMachine
from pysphere.resources import VimService_services as VI
from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect, Disconnect
from master_include import *
from ConfigParser import SafeConfigParser
import requests, json, shutil
from pprint import pprint
import string, random, pickle
import time, atexit


#choice = int(raw_input("Please Enter your choice: "))
# Parsing Config from vmware-auto.cfg file
parser = SafeConfigParser()
parser.read('vmware-auto.cfg')

# Properties to be used for tests
vc_ip = parser.get('vcenter', 'vc_ip')  # vCenter ip address to connect
vc_user = parser.get('vcenter', 'vc_user')      # vCenter username
vc_pwd = parser.get('vcenter', 'vc_pwd')        # vCenter password
guest_name = parser.get('guest', 'guest_name')        # Specify the name of the VM to work on
guest_mem = parser.getint('guest', 'guest_mem')          # Specify memory in MB
guest_cpu = parser.getint('guest', 'guest_cpu')          # Specify the number of virtual CPU
guest_disk_gb = parser.getint('guest', 'guest_disk_gb')  # specify disk size in GB
guest_id = parser.get('guest', 'guest_id')            # vmware guest-id code
guest_ver = parser.get('guest', 'guest_ver')           # version of VMX (v8 is editable via the client)
guest_network = parser.get('guest', 'guest_network')  # network-name
guest_enterbios = parser.getboolean('guest', 'guest_enterbios')   # Set this option to "True" if you want to enter bios after powering on the VM        
template = parser.get('guest', 'template')              # template or source VM name from which we deploy VMs
timeout = parser.getint('guest', 'timeout')              # specify the timeout in sec
vm_amount = parser.getint('guest', 'vm_amount')            # specify the amount of vms 
disk_amount = parser.getint('guest', 'disk_amount')             #specify the amount of disks
snap_amount = parser.getint('guest', 'snap_amount')             #specify the amount of snaps
hierarchy_depth = parser.getint('guest', 'hierarchy_depth')    # Specify the number of levels snap-clone hierarchy should be created
iterations = parser.getint('guest', 'iterations')		# Specify the number of iterations you want to run for a particular test
snap_name = parser.get('guest', 'snap_name')          # Specify the name for base snapshot to be created 
clone_name = parser.get('guest', 'clone_name')  # Specify the name for the clone to be created
datastore = parser.get('host', 'datastore')             # Specify the name of the datastore
esx_host = parser.get('host', 'esx_host')             # specific host to be used
dc = parser.get('host', 'dc')                           # Specify the name of the Datacenter to be used
iso_ds = parser.get('host', 'iso_ds')                 # Datastore of the iso
iso_path = parser.get('host', 'iso_path')             # iso to mount (from datastore) path should be like "<path>/.iso" without / prefix to path
resource_pool = parser.get('host', 'resource_pool')     # specify the resource pool where you want to create VM
cluster = parser.get('host', 'cluster')                         # Specify the cluster name
mgmtip_port = parser.get('Mgmt_server', 'mgmt_ip')      # Specify the maxta management server ip --> mandatory to execute maxta commands
mgmt_user = parser.get('Mgmt_server', 'mgmt_user')        # Specify the maxta management username --> mandatory to execute maxta commands
mgmt_pwd = parser.get('Mgmt_server', 'mgmt_pwd')          # Specify the maxta management password --> mandatory to execute maxta commands
esxiip_port = parser.get('esxi_server', 'esxi_ip')      # Specify the maxta management server ip --> mandatory to execute esxi commands
esxi_user = parser.get('esxi_server', 'esxi_user')        # Specify the maxta management username --> mandatory to execute esxi commands
esxi_pwd = parser.get('esxi_server', 'esxi_pwd')         # Specify the maxta management password --> mandatory to execute esxi commands
ipmi_ip = parser.get('IPMI_server', 'ipmi_ip')          # Specify the ipmi server ipaddress	--> mandatory to execute ipmi commands
ipmi_user = parser.get('IPMI_server', 'ipmi_user')      # Specify the ipmi server username	--> mandatory to execute ipmi commands
ipmi_pwd = parser.get('IPMI_server', 'ipmi_pwd')        # Specify the ipmi server password	--> mandatory to execute ipmi commands
testids =  parser.get('testcase', 'testids')    # Specify the list of testid's to be executed --> mandatory to run tests
username = parser.get('Email', 'username') 		# Specify your email username to login
password = parser.get('Email', 'password')		# Specify you email password to login
recipients = parser.get('Email', 'recipients')  # Specify your recipients to recieve your email


#Conect to VIServer
#host_con = connectToHost(vc_ip,vc_user,vc_pwd)
global host_con
global smart_con

#Listing Hosts 
host_list = esx_host.split(',')
ipmi_list = ipmi_ip.split(',')

def ssh_cmd(cmd,ipaddress,user,pwd):
				# Running command on remote linux machine
				logger1.info("Running command over SSH")
				test = remote_ssh_cmd(cmd,ipaddress,user,pwd)
				logger1.info(test)
				return test

def check_platform():
		platform = sys.platform
		if platform == 'linux2':	
			slash = '/'
			return slash
		elif platform == 'win32':
			slash = '\\'
			return slash
		else:
			logger1.error("Platform unknown...")

check_pf = check_platform()

def diff_file(cmd):
	task = cmd
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out = p.communicate()[0].strip()
	return (out,p.returncode)

def maxta_log_analyzer(download=True,testcase=None,rand_string=None):
		script_file = "Maxta_Log_Analyzer.py"		
		script_src = os.getcwd()+check_pf+script_file		
		logger1.info("Executing the %s script..." %script_file)
		cmd = "python "+script_src+" -m "+mgmtip_port+" -v "+vc_ip+" -u "+vc_user+" -p "+vc_pwd		
		os.system(cmd)
		time.sleep(10)
		if download:
				if rand_string == None:
					rand_string = (''.join(random.choice(string.lowercase) for i in range(5)))
				log_file = "maxta_log_analyzer.log"
				log_src = os.getcwd()+check_pf+"%s" %log_file
				if testcase == None:
						dest_dir = os.getcwd()+check_pf+"Logs"+check_pf
						log_dest = os.getcwd()+check_pf+"Logs"+check_pf+"%s_" %rand_string+log_file
						if not os.path.exists(dest_dir):
								os.makedirs(dest_dir)
						logger1.info("Moving 'maxta_log_analyzer.log' file to %s" %log_dest)
						shutil.move(log_src, log_dest)
				else:
						dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
						log_dest = dest_dir+log_file
						if not os.path.exists(dest_dir):
								os.makedirs(dest_dir)
						logger1.info("Moving 'maxta_log_analyzer.log' file to %s" %log_dest)
						shutil.move(log_src, log_dest)

def cluster_status(rand_string,ip,prelog_include=True,mycmd1=None,mycmd2=None,mycmd3=None,mycmd4=None,mycmd5=None,testcase=None):
		anlyz_file = "maxta_log_analyzer.log"
		pre_file = "staleInode_pre.log"
		post_file = "staleInode_post.log"
		pre_anlyz_file = "Analyzer_pre.log"
		post_anlyz_file = "Analyzer_post.log"
		testcase = str(testcase)
		if testcase:
			dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
			if not os.path.exists(dest_dir):
				os.makedirs(dest_dir)
		else:
			dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+rand_string+check_pf
			if not os.path.exists(dest_dir):
				os.makedirs(dest_dir)
						
		anlyz_file_src = dest_dir+"%s" %anlyz_file
		pre_file_dest = dest_dir+"%s" %pre_file
		post_file_dest = dest_dir+"%s" %post_file
		pre_anlyz_file_dest = dest_dir+"%s" %pre_anlyz_file
		post_anlyz_file_dest = dest_dir+"%s" %post_anlyz_file

		cmd1 = "showInodes --stale"		
		cmd2 = "diff %s %s" %(pre_anlyz_file_dest, post_anlyz_file_dest)	
		cmd3 = "diff %s %s" %(pre_file_dest, post_file_dest)		
		
		# Monitoring the cluster status when host power state changes
		failed_msg = "Somthing wrong!! with maxta storage, after changing power status of %s" %ip
		passed_msg = "Everything looks good so far after changing power status of %s" %ip					
		if prelog_include == True:
			(outdata1, rc1) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
			with open(pre_file_dest, 'w') as file:
				for item in outdata1:
					file.write("%s\n" % item)
			maxta_log_analyzer(testcase=testcase)
			shutil.move(anlyz_file_src, pre_anlyz_file_dest)
			time.sleep(10)
		# Powering off the host
		logger1.info("Executing cmd: %s" %mycmd3)
		eval(mycmd1)
		# Check for intermediat command
		if mycmd5 != None:
			eval(mycmd5)
		time.sleep(120)	
		# Powering on the host
		logger1.info("Executing cmd: %s" %mycmd4)
		eval(mycmd2)
		time.sleep(900)
		(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
                with open(post_file_dest, 'w') as file:
                	for item in outdata2:
                        	file.write("%s\n" % item)
                maxta_log_analyzer(testcase=testcase)
                shutil.move(anlyz_file_src, post_anlyz_file_dest)
                time.sleep(10)
		print cmd2
		(outdata3, rc3) = diff_file(cmd2) 
		if rc3 == 1:
				logger1.error("\n\n%s\n" %failed_msg)						
				return failed_msg 
		else:
				(outdata4, rc4) = diff_file(cmd3)                       
				status = rc4
				while status == 1:
						logger1.info("\n\nFew inodes are still in STALE state\n\n")
						(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
						with open(post_file_dest, 'w') as file:
				                        for item in outdata2:
                                				file.write("%s\n" % item)
						(outdata4, rc4) = diff_file(cmd3)                                
						status = rc4
						if status == 0:
							   break
						time.sleep(600)
				logger1.info("\n\nResync completed...\n\n") 
				maxta_log_analyzer(testcase=testcase)
				shutil.move(anlyz_file_src, post_anlyz_file_dest)
				(outdata3, rc3) = diff_file(cmd2)
				if rc3 == 1:
						logger1.error("\n\n%s\n" %failed_msg)						
						return failed_msg 
				else:
						logger1.info("\n\n%s\n" %passed_msg)
						logger1.info("="*150+"\n")
						subject = "%s test status on %s" %(testcase,cluster)
						send_mail(username,password,my_recipients,subject,passed_msg)

def get_interface():
        cmd = "ifconfig | grep -iE 'mtu'| grep -v lo | awk '{print $1}'"
        p = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out1 = p.communicate()[0]
        out2 = out1.split(":\n")
        return out2[1]


'''ip = '169.254.43.7'

cmd4 = "cat /var/log/zookeeper/zookeeper.log | grep -iE 'TOOK' | awk '{print $8}'"
(outdata, rc) = ssh_cmd(cmd4,ip,mgmt_user,mgmt_pwd)
if re.match("LEADING", outdata[0]):
	print "This node is a LEADING"
else:
	print "This node is a FOLLOWING"'''


def get_obj(content, vimtype, name):
	"""
	Return an object by name, if name is None the
	first found object is returned
	"""
	obj = None			
	container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
	for c in container.view:
		if name:
			if c.name == name:
				obj = c
				break
		else:
			obj = c
			break
	return obj
	
	
vm_name = 'FM-vm1'	
	
get_ipaddr(vm_name)

'''def get_ipaddr(vm_name):
	global smart_con, session_key, session_user
	
	def get_obj(content, vimtype, name):
			"""
			Return an object by name, if name is None the
			first found object is returned
			"""
			obj = None			
			container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
			for c in container.view:
				if name:
					if c.name == name:
						obj = c
						break
				else:
					obj = c
					break
			return obj
	
	try:
		session_status = smart_con.content.sessionManager.SessionIsActive(session_key, session_user)
		logger.debug("Current session status : %s" %session_status)
	except vim.fault.NotAuthenticated:
		logger.info("Session Expired, Reconnecting to vCenter...")
		smart_con, session_key, session_user = smartconnect(vc_ip,vc_user,vc_pwd)

	content = smart_con.RetrieveContent()		
	vm_obj = get_obj(content, [vim.VirtualMachine], vm_name)
			
	summary = vm_obj.summary
   	if summary.guest != None:
		ip = summary.guest.ipAddress
		if ip != None and ip != "":
			print ip
get_ipaddr(vm_name)'''

#--------------------------------------------------------------------

'''name = datastore
#host_con.disconnect()
vm_list = find_vms(name)
print host_con
print vm_list
for vm in vm_list:						
		print find_vm(vm)
		#time.sleep(1800)
		print host_con'''

#--------------------------------------------------------------------
	 
'''name = datastore
vm_list = find_vms(name)
for vm in vm_list:
				print find_vm(vm,host_con)'''

#--------------------------------------------------------------------

'''ipmi_list = ipmi_ip.split(',')
print ipmi_list
for ip in ipmi_list:
				ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power cycle')'''

#---------------------------------------------------------------------
'''vm = find_vm(guest_name,host_con)
user = 'root'
password = 'Sierr@4all' '''


#---------------------------------------------------------------------

				
'''mgmtip = '192.168.4.53'

# Creating a session
s = requests.session()
login_url = 'http://%s/j_spring_security_check' %mgmtip
logout_url = 'http://%s/j_spring_security_logout' %mgmtip
api_url = 'http://%s/api/v3/hosts' %mgmtip
vm_url = 'http://%s/api/v3/vc/vm' %mgmtip
snap_url = 'http://%s/api/v3/task' %mgmtip
spool_info = 'http://%s/api/v3/maxta/StoragePoolInfo' %mgmtip

# Login to maxta mgmt server
login_payload = {'j_vcenter': '192.168.4.81', 'j_username': 'root', 'j_password': 'Vedams@123'}
login = s.post(login_url, data=login_payload)
print login.status_code

# Get hostname from node#0
#api_payload = {'data':'[0]'}
nodes = [] 
r = s.get(spool_info)
print r.status_code
print type(r.content)
string = r.content
dict = json.loads(string)
print type(dict)
print dict
host_len =  len(dict['data'])
print host_len
for i in range(host_len):
	node = dict['data'][i]['ipAddr']
	nodes.append(node)
nodes = sorted(nodes)

print nodes

#print(dict['data'][0]['hostName'])'''

'''# Get vm details
vmlist = {}
vm = s.get(vm_url)
print vm.status_code
string1 = vm.content
dict1 = json.loads(string1)
pprint(dict1)

for i in range(len(dict1['data'])):        
				a = (dict1['data'][i]['vmPathName'])
				b = a.split(' ')
				c = b[1].split('/')
				d = vmlist[c[0]] = (dict1['data'][i]['vmid'])
	
print vmlist
for key, value in vmlist.iteritems():
				if re.match('.*%s.*' %guest_name, key):
								print key+": "+value
								vmid = value
								print vmid '''

'''# Create a maxta snpshot
snap_payload = {'operation': 'SNAPSHOT', 'vmMoid': 'vm-1386' ,'snapName': 'mani-snap1' ,'description': 'desc of snap1'}
snapshot = s.post(snap_url, data=snap_payload)
print snapshot.status_code
string2 = snapshot.content
dict2 = json.loads(string2)
pprint(dict2)

# Generate support bundle


sb_url = 'http://%s/api/v3/supportLog/bundle' %mgmtip
sb_prog = 'http://%s/api/v3/supportLog/bundle/progress' %mgmtip

def downloadFile(url,directory,Filename):    
	r = s.get(url, stream=True)  
	start = time.clock()
	f = open(directory + '\\' + Filename, 'wb')
	for chunk in r.iter_content(chunk_size = 512 * 1024) :
				if chunk :
							f.write(chunk)
							f.flush()
							os.fsync(f.fileno())
	f.close() 

def main() :
	url = sb_url
	directory = os.getcwd()
	Filename = "maxta-system-log.tar.gz.gpg"
	src = os.getcwd()+"\%s" %Filename
	dest = "C:\scripts\Create-VM\Logs"
	downloadFile(url,directory,Filename)  
	time.sleep(10)
	read_log = "cat /var/log/maxta/tomcat/supportBundleRaw-496.log"
	print ssh_cmd(read_log,mgmtip_port,mgmt_user,mgmt_pwd)
	print "Download complete..."
	print "moving sb from %s to %s" %(src, dest)
	if not os.path.exists(dest):
				os.makedirs(dest)
	move = shutil.move(src, dest)
	print move

main()

# Logout session
s.post(logout_url)'''

#-------------------------------------------------------------------------------

#ipmi_cmd(ipmi_ip,ipmi_user,ipmi_pwd,'power cycle')

#------------------------------------------------------------------
'''host_id = ""
host_name = host_con.get_hosts()
for key in host_name:
				a = host_name[key]
				if (a == "192.168.4.7"):
						print key, a
						host_id += key
						print host_id
						break
				
DS = [k for k, v in host_con.get_datastores().items()
						 if v == iso_ds][0]'''

#--------------------------------------------------------------

'''user = 'administrator'
password = 'Vedams123'
path = "C:\\"
file_name = 'vi_server.py'
guest_path = path + file_name
local_path = path + file_name

print guest_get_file(host_con,guest_name,user,password,local_path,guest_path,overwrite=False)'''

#------------------------------------------------------------------------

#vm1.getVmName()
#print vm1.get_properties()
#path = '[Maxta-Dell-R610-Cluster] e55ua/win2k8-1.vmx'

#scp_file(mgmtip_port,mgmt_user,mgmt_pwd,source,destination,copyType='put')

#print relocate_vm(host_con,guest_name,datastore,wait=False)
#print create_maxta_snapshot(host_con,guest_name,snap_name,mgmtip_port,mgmt_user,mgmt_pwd,intrface='eth1')
#print create_maxta_clone(host_con,snap_name,clone_name,mgmtip_port,mgmt_user,mgmt_pwd,dc,myhost,datastore,intrface='eth1')
#clone_cmd = "mxTool -z %s:2181 -c createclone .snapshots/%s:%s-%s" %(mgmtip_port, s_name, c_name_pre, s)
#register_vm(host_con, path, name, dc, myhost, sync_run=True)
#delete_vm(host_con,guest_name,rmfile=False)
#os.system("ipmitool -I lanplus -H 192.168.4.2 -U root -P calvin chassis status")


#disconnect from host
host_con.disconnect()
