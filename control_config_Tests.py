#!/usr/bin/env python
# Author: Manindra T
# Date: 25th-May-2016

from master_include import *
from ConfigParser import SafeConfigParser
from pprint import pprint
import time, atexit
import os, sys, re
import json, shutil
import subprocess
import string, random

try:
		import requests
		
except Exception, e:
		print ("Installing missing modules...")
		os.system("pip install -U requests")
		import requests
		

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
cluster = parser.get('host', 'cluster')                 # Specify the cluster name
nfs_mount = parser.get('host', 'nfs_mount')             # Specify the nfs mount where logs to be saved for Maxta-Log-Analyzer
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


global host_con
global smart_con

#Listing Hosts 
host_list = esx_host.split(',')
ipmi_list = ipmi_ip.split(',')
my_recipients = recipients.split(',')

#Listing testid's
testid = testids.split(',')

check_pf = check_platform()

def vmotion(guest_name,my_host,wait=True):
		# vMotion of a guest VM
		logger1.info("Starting VM migration...")
		test = migrate_vm(guest_name,my_host,wait)
		return test

def vm_clone(guest_name,clone_name,pwron,wait=True):
		# Creating clone from a VM
		logger1.info("Creating a clone from VM")
		test = clone_vm(guest_name,clone_name,pwron,wait)
		return test  

def ssh_cmd(cmd,ipaddress,user,pwd):
		# Running command on remote linux machine
		logger1.info("Running command over SSH")
		test = remote_ssh_cmd(cmd,ipaddress,user,pwd)
		logger1.info(test)
		return test

def add_disk(vm_name,dsk_amount):
		count = 1
		passcount = 0
		while count <= dsk_amount:
			logger1.info("Adding disk %s to %s" %(count,vm_name))
			test = add_disk_vm(vm_name,datastore,guest_disk_gb,wait=True)
			if test == "PASS":
				passcount += 1
			time.sleep(5)
			count += 1
		vm1 = find_vm(vm_name) 
		status = vm1.is_powered_on()    
		if status == True:
				logger1.info("'%s' is already powered on" %vm_name)
				return passcount				
		else: 
				logger1.info("Powering on '%s'" %vm_name)
				powerOnGuest(vm_name)
				logger1.info("%s powered on" %vm_name)
				return passcount

def diff_file(cmd):
	task = cmd
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out = p.communicate()[0].strip()
	return (out, p.returncode)

def maxta_log_analyzer(download=True,testcase=None,rand_string=None):
		script_file = "Mx_Log_Analyzer.py"		
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
						try:
							shutil.move(log_src, log_dest)
						except IOError, e:
							return "FAIL"
						else:
							return "PASS"
				else:
						dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
						log_dest = dest_dir+log_file
						if not os.path.exists(dest_dir):
								os.makedirs(dest_dir)
						logger1.info("Moving 'maxta_log_analyzer.log' file to %s" %log_dest)
						try:
							shutil.move(log_src, log_dest)
						except IOError, e:
							return "FAIL"
						else:
							return "PASS"
				

def gen_support_bundle(testcase=None):
		# Generate maxta support bundle and copy log file to log directory
		# Creating a session
		mgmtip = mgmtip_port
		s = requests.session()
		login_url = 'http://%s/j_spring_security_check' %mgmtip
		logout_url = 'http://%s/j_spring_security_logout' %mgmtip
		sb_url = 'http://%s/api/v3/supportLog/bundle' %mgmtip
		# Login to maxta mgmt server
		login_payload = {'j_vcenter': vc_ip, 'j_username': vc_user, 'j_password': vc_pwd}
		login = s.post(login_url, data=login_payload)
		login_status =  login.status_code
		if str(login_status) == '200':
				logger1.info("Login to maxta mgmt server successful!!!")
		else:
				logger1.error("Failed to login to maxta mgmt server with status code '%s'" %login_status)
		
		# Generate support bundle
		def downloadFile(url,directory,Filename):
				logger1.info("Generating maxta support bundle, Please wait...")
				r = s.get(url, stream=True)
				start = time.clock()
				f = open(directory + check_pf + Filename, 'wb')
				for chunk in r.iter_content(chunk_size = 512 * 1024):
						if chunk:
								f.write(chunk)
								f.flush()
								os.fsync(f.fileno())
				f.close() 
		
		url = sb_url
		directory = os.getcwd()
		Filename = "maxta-system-log.tar.gz.gpg"
		rand_string = (''.join(random.choice(string.lowercase) for i in range(5)))
		src = os.getcwd()+check_pf+"%s" %Filename
		dest = os.getcwd()+check_pf+"Logs"+check_pf+"Support-%s" %rand_string
		tc_dest = os.getcwd()+check_pf+"Logs"+check_pf+"%s" %testcase
		downloadFile(url,directory,Filename)
		time.sleep(10)
		read_log = "cat /var/log/maxta/tomcat/supportBundleRaw-496.log"
		logger1.info(ssh_cmd(read_log,mgmtip_port,mgmt_user,mgmt_pwd))
		logger1.info("Download complete...")
		if testcase == None:                
				logger1.info("moving sb from %s to %s" %(src, dest))
				if not os.path.exists(dest):
						os.makedirs(dest)
				time.sleep(10)
				try:
					shutil.move(src, dest)
				except IOError, e:
					return "FAIL"
				else:
					return "PASS"

		else:
				logger1.info("moving sb from %s to %s" %(src, tc_dest))
				if not os.path.exists(tc_dest):
						os.makedirs(tc_dest)
				time.sleep(10)
				try:
					shutil.move(src, tc_dest)					
				except IOError, e:
					return "FAIL"
				else:
					return "PASS"

		# Logout session
		s.post(logout_url)


def cluster_status(ip,prelog_include=True,mycmd1=None,mycmd2=None,mycmd3=None,mycmd4=None,mycmd5=None,testcase=None,rand_string=None):
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
			logger1.info("Renaming '%s' to '%s'" %(anlyz_file,pre_anlyz_file))
			time.sleep(10)
		# Powering off the host
		logger1.info("Executing cmd: %s" %mycmd3)
		#eval(mycmd1)
		# Check for intermediat command
		if mycmd5 != None:
			eval(mycmd5)
		time.sleep(120)	
		# Powering on the host
		logger1.info("Executing cmd: %s" %mycmd4)
		#eval(mycmd2)
		time.sleep(900)
		(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(post_file_dest, 'w') as file:
			for item in outdata2:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, post_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
		time.sleep(10)
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
				logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
				(outdata3, rc3) = diff_file(cmd2)
				if rc3 == 1:
						logger1.error("\n\n%s\n" %failed_msg)						
						return failed_msg 
				else:
						logger1.info("\n\n%s\n" %passed_msg)
						logger1.info("="*150+"\n")
						subject = "%s test status on %s" %(testcase,cluster)
						send_mail(username,password,my_recipients,subject,passed_msg)
		return passed_msg
				
def ss_test1(guest_name,snap_name,mem=True,quice=False):
		# Snapshot of VM when it is shutdown(sc-2)
		# mem and quice should be either True or False.
		# power off vm		
		powerOffGuest(guest_name)
		logger1.info("%s powered off" %guest_name)
		time.sleep(10)
		# Create vmware snapshot of a VM
		test = create_vmware_snapshot(guest_name,dc,snap_name,mem,quice)
		logger2.info("ss_test1 : "+ test)        
		time.sleep(10)
		return test

def ss_test2(guest_name,snap_name,mem=True,quice=False):
		# Snapshot of VM with IO running on it(sc-1)
		# mem and quice should be either True or False.
		# power on vm		
		powerOnGuest(guest_name)
		logger1.info("%s powered on" %guest_name)
		time.sleep(10)
		# Create vmware snapshot of a VM
		test = create_vmware_snapshot(guest_name,dc,snap_name,mem,quice)
		logger2.info("ss_test2 : "+ test)        
		time.sleep(10)
		return test
		
def ss_test3(guest_name,snap_name,clone_name,pwron=True,wait=True):
		# Snapshot a running VM, create a clone of the VM and start IO on the clone.(sc-4)				
		# Snapshot a runnign VM
		test1 = ss_test2(guest_name,snap_name)
		if test1 == "FAIL":
			logger2.info("ss_test3 : "+ test1)
			return test1
		# Create clone of the VM
		test2 = vm_clone(guest_name,clone_name,pwron,wait)
		logger2.info("ss_test3 : "+ test2)        
		time.sleep(30)
		return test2
		
def ss_test4(guest_name,snap_name,clone_name):
		# Snapshot of VM, clone VM, vMotion clone to other host, vMotion back to original host(sc-9)
		# snapshot and clone VM
		test3_clone = find_vm(clone_name)
		if test3_clone == None:
			test3 = ss_test3(guest_name,snap_name,clone_name)
			if test3 == "FAIL":
				logger2.info("ss_test4 : "+ test3)
				return
		# vMotion clone to another host and back to original host
		count = 0
		for i in range(len(host_list)):
				my_host = host_list[i]
				logger1.info('Migrating "%s" to %s' %(clone_name,my_host))
				test1 = vmotion(clone_name,my_host,wait=True)
				if test1 == "FAIL":
					logger2.info("ss_test4 : "+ test1)
					return
				time.sleep(30)
				count += i				
		my_host = host_list[0]
		logger1.info('Migrating "%s" to %s' %(clone_name,my_host))
		test2 = vmotion(clone_name,my_host,wait=True)        
		logger2.info("ss_test4 : "+ test2)
		return 

def vM_test5(guest_name):
		# During guest VM migration, shutdown third Host (other than the source or destination host)(vMotion-5)          
		if len(host_list) < 3:
				logger1.warning("Please specify minimum 3 hosts in %s" %cluster)
				logger2.info("vM_test5 : FAIL")
		else:
				my_host = host_list[0]
				logger1.info("Trying to migrate '%s' to host '%s'" %(guest_name, my_host))
				test1 = vmotion(guest_name,my_host,wait=True)
				if test1 == "FAIL":
					logger2.info("vM_test5 : "+ test1)
					return
				my_host = host_list[1]
				logger1.info("Trying to migrate '%s' to host '%s'" %(guest_name, my_host))
				test2 = vmotion(guest_name,my_host,wait=False)
				logger2.info("vM_test5 : "+ test2)					
				cmd = "reboot"
				ssh_cmd(cmd,host_list[2],esxi_user,esxi_pwd)
				time.sleep(60)
				ping_status = ping(host_list[2])
				while ping_status != 0:
					logger1.info("waiting 120 secs")
					time.sleep(120)
					ping_status = ping(host_list[2])
				logger1.info("%s is now up and running" %(host_list[2]))

def cl_test6(clone_name):
		# Deploy a clone/clones, add a new disk and power on VM
		curdir = os.getcwd()
		dsk_amount = 1		
		dsk_passcount = 0
		# Verify the VM existance
		mylist = find_vms(clone_name)		
		if len(mylist) == int(0):
				# Clone creation
				for i in range (1, vm_amount+1):
					vmname = clone_name+str(i)
					if i == vm_amount:
						time.sleep(120)
						test2 = clone_from_template(template,vmname,dc,datastore,cluster,wait=True)
					else:
						test1 = clone_from_template(template,vmname,dc,datastore,cluster,wait=False)
						time.sleep(5)
				vm_list = find_vms(clone_name)
				# Add disk operation				        
				logger1.info(vm_list)				
				while len(vm_list) == 0:                        
						logger1.info("Retrying Finding VMs with "+ clone_name + " prefix/suffix")
						vm_list = find_vms(clone_name)
						logger1.info(vm_list)
						time.sleep(30)
				for vm in vm_list:
						logger1.info("Trying to add disk to '%s'" %vm)
						vm1 = find_vm(vm)      
						status = vm1.is_powered_on()    
						while status != True:
								status = vm1.is_powered_on()
								logger1.info("Waiting for '%s' to power on" %vm)
								time.sleep(10)						
						test3 = add_disk(vm,dsk_amount)
						dsk_passcount += test3
						time.sleep(10)
						rebootGuest(vm)
				if len(vm_list) == vm_amount and dsk_passcount == (dsk_amount * vm_amount):
					logger2.info("All the VMs are deployed and new disks are added successfully")
					logger2.info("cl_test6 : PASS")
				elif len(vm_list) == vm_amount and dsk_passcount != (dsk_amount * vm_amount):
					logger2.error("All the VMs are deployed successfully, but new disk addtion failed on one or more VMs")
					logger2.info("cl_test6 : PASSED WITH EXCEPTION")
				else:
					logger2.error("Not all the VMs are deployed successfully or disk addtion failed on one or more VMs")
					logger2.info("cl_test6 : FAIL")
		else:
				logger1.info("VM/VMs already exist...\n")
				vm_list = find_vms(clone_name)
				# Add disk operation				       
				logger1.info(vm_list)				
				while len(vm_list) == 0:                        
						logger1.info("Retrying Finding VMs with "+ clone_name + " prefix/suffix")
						vm_list = find_vms(clone_name)
						logger1.info(vm_list)
						time.sleep(20)
				for vm in vm_list:
						logger1.info("Trying to add disk to '%s'" %vm)
						vm1 = find_vm(vm)      
						status = vm1.is_powered_on()    
						while status != True:
								status = vm1.is_powered_on()
								logger1.info("Waiting for '%s' to power on" %vm)
								time.sleep(10)						
						test4 = add_disk(vm,dsk_amount)
						dsk_passcount += test4
						rebootGuest(vm)
				if dsk_passcount == (dsk_amount * vm_amount):
					logger2.info("New disks addtion to all the VMs was successful")
					logger2.info("cl_test6 : PASS")
				else:
					logger2.error("Failed to add disks to all the VMs")
					logger2.info("cl_test6 : FAIL")

def vM_test7(clone_name):
		# Migrate 10 Guest VM at the same time from one host to another(vMotion-6, vMotion-9)
		### vMotion multiple VMs at a time and loop through all the nodes ###
		failcount = 0
		vm_list = find_vms(clone_name)
		logger1.info("List of VMs found to migrate : %s" %vm_list)
		if len(host_list) < 3:
				logger1.warning("Please specify minimum 3 hosts in %s" %cluster)
				logger2.info("vM_test7 : FAIL")
		elif len(vm_list) < 9:
				logger1.warning("Please create minimum 10 vms with name in 'clone_name' and try again")
				logger2.info("vM_test7 : FAIL")
		else:                              
				for i in range(len(host_list)):
						vm_list = find_vms(clone_name)                        
						my_host = host_list[i]
						logger1.info("List of vms found to migrate: %s" %vm_list)                        
						for vm in vm_list:
								if vm == vm_list[-1:][0]:
										logger1.info("Trying to migrate '%s' to host '%s'" %(vm,my_host))
										time.sleep(30)
										test2 = vmotion(vm,my_host,wait=True)
										if test2 == "FAIL":
											failcount += 1
										break 
								logger1.info("Trying to migrate '%s' to host '%s'" %(vm,my_host))
								test1 = vmotion(vm,my_host,wait=False)
								if test1 == "FAIL":
									failcount += 1									
						logger1.info("Migration to host %s done" %my_host)                        
						if failcount >= 1:
							logger2.error("Failed to migrated to migrate all the VM to %s" %my_host)
							logger2.info("vM_test7 : FAIL")
							return
						else:
							logger2.info("All the VMs are migrated to %s successfully" %my_host)							
						# reset failcount
						failcount = 0
						time.sleep(60)
				logger2.info("vM_test7 : PASS")

def ss_test8(guest_name,snap_name,snap_amount):
		#Create multiple maxta snapshots
		failcount = 0
		for i in range(1, snap_amount+1):
				sname = snap_name+str(i)
				logger1.info("Creating maxta snapshot of VM '%s'" %(guest_name))
				test = create_maxta_snapshot(guest_name,sname,mgmtip_port,mgmt_user,mgmt_pwd,intrface='ens192')
				logger1.info("Waiting 30 seconds for snapshot operation to complete...")
				time.sleep(30)
				if test == "FAIL":
						failcount += 1
		if failcount >= 1:
			logger2.error("Not all snapshots are created successfully...")
			logger2.info("ss_test8 : FAIL")
		else:
			logger2.info("All the snapshot are created successfully...")
			logger2.info("ss_test8 : PASS")

def ss_test9(snap_name,clone_name,vm_amount):        
		#Create multiple maxta clones
		hostcount = len(host_list)
		count = 0
		vmcount = 1
		failcount = 0
		while (vmcount <= vm_amount) and (count <= hostcount):
				vm_name = '%s%s' %(clone_name,vmcount)
				myhost = host_list[count]
				logger1.info("Creating maxta clone '%s' from snapshot '%s'" %(vm_name,snap_name))
				test = create_maxta_clone(snap_name,vm_name,mgmtip_port,mgmt_user,mgmt_pwd,dc,myhost,datastore,intrface='ens192')
				count += 1
				vmcount += 1
				if (count == hostcount) and (vmcount <= vm_amount):
						#Reset the count to 0
						count = 0
				if test == "FAIL":
						failcount += 1                
		if failcount >= 1:
				logger2.error("Not all clones are created successfully...")
				logger2.info("ss_test9 : FAIL")
		else:
				logger2.info("All the clones are created successfully...")
				logger2.info("ss_test9 : PASS")
						
def vM_test10(guest_name,iso_ds,wait=True):
		#perform storage vMotion of a VM from maxta DS to non maxta DS, but not host
		logger1.info("Starting VM storage migration from %s to %s" %(datastore, iso_ds))
		test1 = relocate_vm(guest_name,iso_ds,wait=True)		
		test2 = relocate_vm(guest_name,datastore,wait=True)
		if (test1 == 'FAIL') & (test2 == 'PASS'):
			logger2.error("storage vMotion from maxta DS to Non maxta DS failed")
			logger2.info("vM_test10 : FAIL")
		elif (test1 == 'PASS') & (test2 == 'FAIL'):
			logger2.error("storage vMotion from Non maxta DS to maxta DS failed")
			logger2.info("vM_test10 : FAIL")
		elif (test1 == 'FAIL') & (test2 == 'FAIL'):
			logger2.error("storage vMotion to and fro from maxtaDS to Non maxtaDS failed")
			logger2.info("vM_test10 : FAIL")
		else:
			logger2.info("vM_test10 : PASS")
			
def vM_test11(guest_name,iso_ds,wait=True):
		#perform storage vMotion of a VM from maxta DS to non maxta DS and to a different host
		if len(host_list) <= 2:
				logger1.warning("Please specify more than 2 hosts under 'esx_host' in the config file")
		else:
				host = host_list[1]                
				logger1.info("Starting VM storage migration from %s to %s" %(datastore, iso_ds))
				test1 = relocate_vm(guest_name,iso_ds,host,wait)
				test2 = relocate_vm(guest_name,datastore,host,wait)
				if (test1 == 'FAIL') & (test2 == 'PASS'):
					logger2.error("storage vMotion from maxtaDS to Non maxtaDS failed")
					logger2.info("vM_test10 : FAIL")
				elif (test1 == 'PASS') & (test2 == 'FAIL'):
					logger2.error("storage vMotion from Non maxtaDS to maxtaDS failed")
					logger2.info("vM_test10 : FAIL")
				elif (test1 == 'FAIL') & (test2 == 'FAIL'):
					logger2.error("storage vMotion to and fro from maxtaDS to Non maxtaDS failed")
					logger2.info("vM_test10 : FAIL")
				else:
					logger2.info("vM_test10 : PASS")
					

def ss_test12(guest_name):
		# maxta snap-clone hiearachy 1
		snap_failcount = 0
		clone_failcount = 0
		scount = 1
		ccount = 1
		hostcount = len(host_list)       
		hcount = 0        
		snap_name = 'H1_S'
		clone_name = 'H1_C'
		logger1.info("Starting maxta snap-clone hieracy-1 test")        
		logger1.info("Creating maxta snapshot '%s%s'" %(snap_name,scount))
		test1 = create_maxta_snapshot(guest_name,snap_name+str(scount),mgmtip_port,mgmt_user,mgmt_pwd,intrface='ens192')
		if test1 == 'FAIL':
			snap_failcount += 1
		time.sleep(5)
		logger1.info("Creating maxta clone '%s%s'" %(clone_name,ccount))
		test2 = create_maxta_clone(snap_name+str(scount),clone_name+str(ccount),mgmtip_port,mgmt_user,mgmt_pwd,dc,host_list[hcount],datastore,intrface='ens192')
		if test2 == 'FAIL':
			clone_failcount += 1
		time.sleep(120)       
		scount += 1
		hcount += 1       
		while (scount <= hierarchy_depth) and (hcount <= hostcount):
				logger1.info("Creating maxta snapshot '%s%s'" %(snap_name,scount))
				test1 = create_maxta_snapshot(clone_name+str(ccount),snap_name+str(scount),mgmtip_port,mgmt_user,mgmt_pwd,intrface='ens192')
				if test1 == 'FAIL':
					snap_failcount += 1
				time.sleep(30)
				ccount += 1
				logger1.info("Creating maxta clone '%s%s'" %(clone_name,ccount))
				test2 = create_maxta_clone(snap_name+str(scount),clone_name+str(ccount),mgmtip_port,mgmt_user,mgmt_pwd,dc,host_list[hcount],datastore,intrface='ens192')
				if test2 == 'FAIL':
					clone_failcount += 1
				time.sleep(120)
				scount += 1 
				hcount += 1
				if (hcount == hostcount) and (scount <= hierarchy_depth):
						#Reset the hcount to 0                        
						hcount = 0

				if (snap_failcount >= 1) & (clone_failcount == 0):
					logger2.error("Not all snapshots are created successfully...")
					logger2.info("ss_test12 : FAIL")
					return
				elif (snap_failcount == 0) & (clone_failcount >= 1):
					logger2.error("Not all clones are created successfully...")
					logger2.info("ss_test12 : FAIL")
					return
				elif (snap_failcount >= 1) & (clone_failcount >= 1):
					logger2.error("Not all snapshots and clones are created successfully...")
					logger2.info("ss_test12 : FAIL")
					return
				else:
					pass
		logger2.info("All the snapshots and clones are created successfully in hiearachy-1...")
		logger2.info("ss_test12 : PASS")
		logger1.info("Successfully completed snap-clone hierarcy-1 test")


def ss_test13(guest_name):
		# maxta snap-clone hiearachy 2
		snap_failcount = 0
		clone_failcount = 0
		gname = ""
		depth_count = 1
		count = 1        
		hostcount = len(host_list)       
		hcount = 0              
		snap_name = 'H2_S'
		clone_name = 'H2_C'        
		logger1.info("Starting maxta snap-clone hieracy-2 test")
		sname = []
		cname = []
		new_sname = []
		new_cname = []  
		while depth_count <= hierarchy_depth:                              
				if len(sname) == 0:
						while (count <= 3) and (hcount <= hostcount):                               
								logger1.info("Creating maxta snapshot '%s%s'" %(snap_name,count))
								sname.append(snap_name+str(count))
								test1 = create_maxta_snapshot(guest_name,snap_name+str(count),mgmtip_port,mgmt_user,mgmt_pwd,intrface='ens192')            
								if test1 == 'FAIL':
									snap_failcount += 1
								time.sleep(5)
								logger1.info("Creating maxta clone '%s%s'" %(clone_name,count))
								cname.append(clone_name+str(count))
								test2= create_maxta_clone(snap_name+str(count),clone_name+str(count),mgmtip_port,mgmt_user,mgmt_pwd,dc,host_list[hcount],datastore,intrface='ens192')
								if test2 == 'FAIL':
									clone_failcount += 1
								time.sleep(60)
								count += 1                                
								hcount += 1
								if (hcount == hostcount) and (count <= 3):
										#Reset the hcount to '0'                        
										hcount = 0
						
						logger1.info("List of snapshots created: %s" %sname)
						logger1.info("List of clones created : %s" %cname)
						# Resetting the count to '0'
						count = 1                        
						if (hcount == hostcount):
								#Reset the hcount to '0'                      
								hcount = 0                                
											   
				else:                       
						scount = 0
						for vm in cname:                                
								snap_name = sname[scount]
								while (count <= 3) and (hcount <= hostcount):                                        
										logger1.info("Creating maxta snapshot '%s%s'" %(snap_name,count))
										new_sname.append(snap_name+str(count))
										test1 = create_maxta_snapshot(vm,snap_name+str(count),mgmtip_port,mgmt_user,mgmt_pwd,intrface='ens192')            
										if test1 == 'FAIL':
											snap_failcount += 1
										time.sleep(30)
										logger1.info("Creating maxta clone '%s%s'" %(vm,count))
										new_cname.append(vm+str(count))
										test2 = create_maxta_clone(snap_name+str(count),vm+str(count),mgmtip_port,mgmt_user,mgmt_pwd,dc,host_list[hcount],datastore,intrface='ens192')
										if test2 == 'FAIL':
											clone_failcount += 1
										time.sleep(60)                                        
										count += 1
										hcount += 1                                        
										if (hcount == hostcount) and (count <= 3):
												#Reset the hcount to '0'                      
												hcount = 0
								scount += 1
								count = 1
								# Resetting the scount and ccount to '0'
								if (hcount == hostcount):
										#Reset the hcount to 0                       
										hcount = 0  
						logger1.info("List of snapshots created: %s" %new_sname)
						logger1.info("List of clones created : %s" %new_cname)
						sname = list(new_sname)
						cname = list(new_cname)
						del new_sname[:]
						del new_cname[:]

				if (snap_failcount >= 1) & (clone_failcount == 0):
					logger2.error("Not all snapshots are created successfully...")
					logger2.info("ss_test13 : FAIL")
					return
				elif (snap_failcount == 0) & (clone_failcount >= 1):
					logger2.error("Not all clones are created successfully...")
					logger2.info("ss_test13 : FAIL")
					return					
				elif (snap_failcount >= 1) & (clone_failcount >= 1):
					logger2.error("Not all snapshots and clones are created successfully...")
					logger2.info("ss_test13 : FAIL")                        
					return
				else:
					pass
				
				depth_count += 1

		logger2.info("All the snapshots and clones are created successfully in hiearachy-2...")
		logger2.info("ss_test13 : PASS")                             
		logger1.info("Successfully completed snap-clone hierarcy-2 test")

def sb_test14(testcase=None):
		global host_con
		# Generate support bundle when all the nodes are up and running
		name = datastore
		mxvm_list = find_vms(name)
		for vm in mxvm_list:
				# Verify the VM exists
				logger1.info ('Finding VM %s' % vm)
				src_vm = find_vm(vm)
				if src_vm is None:
						logger1.error ('ERROR: %s not found' % vm)
						logger.info("powerOff: Reconnecting to VIServer...")
						host_con = connectToHost(vc_ip,vc_user,vc_pwd)
						vm = host_con.get_vm_by_name(guest_name)
						src_vm = vm					
				logger1.info('Virtual Machine %s found' % vm)
				vm_status = src_vm.get_status()
				if vm_status == "POWERED ON":
						logger1.info("%s is powered on" %vm)
				else:
						logger1.error("One of the maxta VMs are powered off, \
									 Make sure all the maxta VMs are up and running before stating the test")
						break
		# Starting support bundle generation
		test = gen_support_bundle(testcase)
		if test == "FAIL":
			logger2.error("Support bundle generation failed...")
			logger2.info("ss_test14 : FAIL")
		else:
			logger2.error("Support bundle generation was successful...")
			logger2.info("ss_test14 : PASS")



def ct_test15(testcase):
		# Crash test by powering off maxta VM
		name = datastore
		vm_list = find_vms(name)
		test_complete = "Test completed, Please check the logs for any issues..."
		anlyz_file = "maxta_log_analyzer.log"
		pre_file = "staleInode_pre.log"
		post_file = "staleInode_post.log"
		pre_anlyz_file = "Analyzer_pre.log"
		post_anlyz_file = "Analyzer_post.log"
		testcase = str(testcase)
		dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
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
		
		logger1.info("Maxta VMs found: %s" %vm_list)
		(outdata1, rc1) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(pre_file_dest, 'w') as file:
			for item in outdata1:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, pre_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,pre_anlyz_file))
		time.sleep(10)
		for vm in vm_list:
				failed_msg = "Somthing wrong!! with maxta storage after crashing %s" %vm
				passed_msg = "Everything looks good on %s!!, Moving to another node" %vm
				logger1.info("Powering off maxta VM: %s\n" %vm)
				powerOffGuest(vm)
				time.sleep(300)
				logger1.info("Powering on maxta VM: %s\n" %vm)
				powerOnGuest(vm)
				time.sleep(180)
				(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
				with open(post_file_dest, 'w') as file:
					for item in outdata2:
						file.write("%s\n" % item)
				maxta_log_analyzer(testcase=testcase)
				shutil.move(anlyz_file_src, post_anlyz_file_dest)
				logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
				time.sleep(10)
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
						logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
						(outdata3, rc3) = diff_file(cmd2)
						if rc3 == 1:
								logger1.error("\n\n%s\n" %failed_msg)
								return failed_msg
						else:
								logger1.info("\n\n%s\n" %passed_msg)
								logger1.info("="*150+"\n")								
								subject = "Crash test ct_test15 on %s" %cluster
								send_mail(username,password,my_recipients,subject,passed_msg)
		logger1.info("\n\n%s\n" %test_complete)
		return test_complete

						
def ct_test16(testcase):
		# Crash test by killing mfsd process on maxta VM
		name = datastore
		vm_list = find_vms(name)
		process = '/usr/bin/mfsd -f /etc/maxta/mfsd.cfg'
		ppath = '/usr/bin/mfsctl.sh'
		test_complete = "Test completed, Please check the logs for any issues..."		
		anlyz_file = "maxta_log_analyzer.log"
		pre_file = "staleInode_pre.log"
		post_file = "staleInode_post.log"
		pre_anlyz_file = "Analyzer_pre.log"
		post_anlyz_file = "Analyzer_post.log"
		testcase = str(testcase)
		dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
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
		cmd4 = "mxsplash.sh | grep -iE 'DEBUG is'"

		logger1.info("Maxta VMs found: %s" %vm_list)
		(outdata1, rc1) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(pre_file_dest, 'w') as file:
			for item in outdata1:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, pre_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,pre_anlyz_file))
		time.sleep(10)
		for vm in vm_list:
				failed_msg = "Somthing wrong!! with maxta storage after crashing %s" %vm
				passed_msg = "Everything looks good on %s!!, Moving to another node" %vm
				logger1.info("Killing mfsd process on maxta VM: %s" %vm)
				pid = list_guest_process(vm,mgmt_user,mgmt_pwd,search_str=process)
				kill_process(vm,mgmt_user,mgmt_pwd,pid)
				time.sleep(300)
				(outdata, rc) = ssh_cmd(cmd4,mgmtip_port,mgmt_user,mgmt_pwd)				
				if re.findall("DEBUG is ENABLED!", outdata[0]):
					logger1.info("Starting mfs service on maxta VM: %s" %vm)
					start_Process(vm,mgmt_user,mgmt_pwd,ppath,args=['start'])
					time.sleep(180)
				(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
				with open(post_file_dest, 'w') as file:
					for item in outdata2:
						file.write("%s\n" % item)
				maxta_log_analyzer(testcase=testcase)
				shutil.move(anlyz_file_src, post_anlyz_file_dest)
				logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
				time.sleep(10)
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
						logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
						(outdata3, rc3) = diff_file(cmd2)
						if rc3 == 1:
								logger1.error("\n\n%s\n" %failed_msg)
								return failed_msg
						else:
								logger1.info("\n\n%s\n" %passed_msg)
								logger1.info("="*150+"\n")
								subject = "Crash test ct_test16 on %s" %cluster
								send_mail(username,password,my_recipients,subject,passed_msg)
		logger1.info("\n\n%s\n" %test_complete)
		return test_complete


def vM_test17(clone_name):
		#Migrate Couple of Guest VMs with IO to another host at a time and back to original host(vMotion-7)        
		if len(host_list) < 2:
				logger1.warning("Please specify minimum 3 hosts in %s" %cluster)
		else:
				failcount = 0
				vm_list = find_vms(clone_name)
				logger1.info("List of vms found to migrate: %s" %vm_list)                           
				for vm in vm_list:
						my_host = host_list[1]
						if vm == vm_list[-1:][0]:
								logger1.info("Trying to migrate '%s' to host '%s'" %(vm,my_host))
								time.sleep(10)
								test1 = vmotion(vm,my_host,wait=True)
								if test1 == "FAIL":
									failcount += 1
								break
						logger1.info("Trying to migrate '%s' to host '%s'" %(vm,my_host))
						test1 = vmotion(vm,my_host,wait=False)
						if test1 == "FAIL":
							failcount += 1                                
						logger1.info("Migration to host %s done" %my_host)                        
						time.sleep(60)
				for vm in vm_list:
						my_host = host_list[0]
						logger1.info("Trying to migrate back '%s' to host '%s'" %(vm,my_host))						
						test2 = vmotion(guest_name,my_host,wait=False)
						if test2 == "FAIL":
							failcount += 1
						logger1.info("Migrating back to host %s done" %my_host)
				if failcount >= 1:
					logger2.error("Not all the VMs migrated successfully...")
					logger2.info("vM_test17 : FAIL")
				else:
					logger2.error("All the VMs migrated successfully...")
					logger2.info("vM_test17 : PASS")
						

def ha_test18(vm_name,testcase):
		# Power off one of the hosts in a cluster with HA enabled, All the VMs with IO running,
		# few maxta snapshots and clone should migrate to another node and power on automatically. 
		test_complete = "Test completed, Please check the logs for any issues..."
		# Creating a VM from template and start IO
		cl_test6(vm_name)
		# Create maxta snapshot of the VM created
		sname = 'test18_snap'
		vm_name = vm_name+"1"
		ss_test8(vm_name,sname,snap_amount)
		# Create maxta clone from the snapshot
		sname = sname+"1"
		cname = 'test18_clone'
		ss_test9(sname,cname,vm_amount)
		# Monitor the cluster status when host power status changed
		string1 = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power off')"
		string2 = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power on')" 
		poweroff = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power off')" 
		poweron = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power on')" 
		prelog = True
		for ip in ipmi_list:			
			test = cluster_status(ip,prelog_include=prelog,mycmd1=poweroff,mycmd2=poweron,mycmd3=string1,mycmd4=string2,mycmd5=None,testcase=testcase)
			prelog = False
			if re.match('Somthing wrong!!', test):
				return test				
		logger1.info("\n\n%s\n" %test_complete)
		return test_complete

def ha_test19(vm_name,testcase):
		# Power off all the esxi hosts at a time and power on after few minutes 
		# Creating a VM from template and start IO
		cl_test6(vm_name)
		# Create maxta snapshot of the VM created
		sname = 'test19_snap'
		vm_name = vm_name+"-1"
		ss_test8(vm_name,sname,snap_amount)
		# Create maxta clone from the snapshot
		sname = sname+"-1"
		cname = 'test19_clone'
		ss_test9(sname,cname,vm_amount)
		# Monitor the cluster status when host power status changed
		string1 = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power off')"
		string2 = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power on')" 
		poweroff = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power off')" 
		poweron = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power on')" 
		# Analyzer section
		anlyz_file = "maxta_log_analyzer.log"
		pre_file = "staleInode_pre.log"
		post_file = "staleInode_post.log"
		pre_anlyz_file = "Analyzer_pre.log"
		post_anlyz_file = "Analyzer_post.log"
		testcase = str(testcase)
		dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
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
		failed_msg = "Somthing wrong!! with maxta storage after crashing all the nodes"
		passed_msg = "Everything looks good!!"
		test_complete = "Test completed, Please check the logs for any issues..."
		(outdata1, rc1) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(pre_file_dest, 'w') as file:
			for item in outdata1:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, pre_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,pre_anlyz_file))
		time.sleep(10)
		for ip in ipmi_list:				
			time.sleep(10)
			logger1.info("Executing cmd: %s" %string1)
			eval(poweroff)
		time.sleep(120)
		for ip in ipmi_list:
			time.sleep(10)
			logger1.info("Executing cmd: %s\n" %string2)
			eval(poweron)
		time.sleep(900)
		(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(post_file_dest, 'w') as file:
			for item in outdata2:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, post_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
		time.sleep(10)
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
				logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))				
				(outdata3, rc3) = diff_file(cmd2)
				if rc3 == 1:
						logger1.error("\n\n%s\n" %failed_msg)
						return failed_msg
				else:
						logger1.info("\n\n%s\n" %passed_msg)
						logger1.info("="*150+"\n")
						subject = "HA test ha_test19 on %s" %cluster
						send_mail(username,password,my_recipients,subject,passed_msg)
		logger1.info("\n\n%s\n" %test_complete)
		return test_complete	
					 
			
def ha_test20(vm_name,testcase):
		# vMotion all the VMs to host1 and Powercycle host1, all the VMs on that host should migrate to another host.	
		if len(host_list) < 3 and len(ipmi_list) < 3:
				logger1.warning("Please specify minimum 3 hosts in both esx_host and ipmi_ip in %s" %cluster)
		else:   
				test_complete = "Test completed, Please check the logs for any issues..."
				# Creating a VM from template and start IO
				cl_test7()

				# vMotion of VMs to another host
				prelog = True
				host_count = 0
				for ip in ipmi_list:
					if host_count <= len(host_list):
						vm_list = find_vms(vm_name)						                        
						my_host = host_list[host_count]
						logger1.info("List of vms found to migrate: %s" %vm_list)
						for vm in vm_list:
								if vm == vm_list[-1:][0]:
										logger1.info("Trying to migrate '%s' to host '%s'" %(vm,my_host))
										time.sleep(10)
										vmotion(vm,my_host,wait=True)                                        
										break
								logger1.info("Trying to migrate '%s' to host '%s'" %(vm,my_host))
								vmotion(vm,my_host,wait=False)                                
						logger1.info("Migration to host %s done" %my_host)
						host_count += 1                        
						time.sleep(60)				

					# Monitor the cluster status when host power status changed
					string1 = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power off')"
					string2 = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power on')" 
					poweroff = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power off')" 
					poweron = "ipmi_cmd(ip,ipmi_user,ipmi_pwd,'power on')" 		

					# Analyzer section		
					test = cluster_status(ip,prelog_include=prelog,mycmd1=poweroff,mycmd2=poweron,mycmd3=string1,mycmd4=string2,mycmd5=None,testcase=testcase)
					prelog = False
					if re.match('Somthing wrong!!', test):
						return test						
				logger1.info("\n\n%s\n" %test_complete)
				return test_complete
					
def ss_test21(vm_name,testcase):
	global vm_amount
	# Create 150 VMs on a cluster and start IO	
	if vm_amount > 1:
		logger1.warning("'vm_amount' is greater than 1, setting it to 1")
		vm_amount = 1
	# Creating a VM from template and starting IO
	cl_test6(clone_name)
	# Analyzer section
	anlyz_file = "maxta_log_analyzer.log"
	pre_file = "staleInode_pre.log"
	post_file = "staleInode_post.log"
	pre_anlyz_file = "Analyzer_pre.log"
	post_anlyz_file = "Analyzer_post.log"
	testcase = str(testcase)
	dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
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
	(outdata1, rc1) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
	with open(pre_file_dest, 'w') as file:
		for item in outdata1:
			file.write("%s\n" % item)
	maxta_log_analyzer(testcase=testcase)
	shutil.move(anlyz_file_src, pre_anlyz_file_dest)
	logger1.info("Renaming '%s' to '%s'" %(anlyz_file,pre_anlyz_file))
	time.sleep(10)

	# Create maxta snpshot of the VM in guest_name
	snap_amount = 1
	guest_name = clone_name+"1"
	ss_test8(guest_name,snap_name,snap_amount)

	# Create maxta clone from the snapshot	
	cname = vm_name
	sname = snap_name+"-1"
	total_clones = 100
	total_clones_update = 0	
	hostcount = len(host_list)
	vms_amount = 5
	count = 0
	vmcount = 1
	while total_clones_update < total_clones:		
		for i in range(vmcount, vms_amount+1):
			vm_name = '%s-%s' %(cname,i)
			myhost = host_list[count]			
			logger1.info("Creating maxta clone '%s' from snapshot '%s'" %(vm_name,sname))
			create_maxta_clone(sname,vm_name,mgmtip_port,mgmt_user,mgmt_pwd,dc,myhost,datastore,intrface='ens192')
			count += 1
			vmcount += 1			
			if (count == hostcount) and (i <= vms_amount):
				#Reset the count to 0
				count = 0
		failed_msg = "Somthing wrong!! with maxta storage after creating %s VMs" %vms_amount
		passed_msg = "Everything looks good! after creating %s VMs" %vms_amount
		test_complete = "Test completed, Please check the logs for any issues..."
		(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(post_file_dest, 'w') as file:
			for item in outdata2:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, post_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
		time.sleep(10)		
		(outdata3, rc3) = diff_file(cmd2)
		if rc3 == 1:
				logger1.error("\n\n%s\n" %failed_msg)
				return failed_msg 
		'''else:
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
				logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
				(outdata3, rc3) = diff_file(cmd2)
				if rc3 == 1:
						logger1.error("\n\n%s\n" %failed_msg)
						return failed_msg
				else:'''
		logger1.info("\n\n%s\n" %passed_msg)
		logger1.info("="*150+"\n")
		subject = "Crash test ss_test21 on %s" %cluster
		send_mail(username,password,my_recipients,subject,passed_msg)
		total_clones_update += 5		
		vms_amount += 5
	logger1.info("\n\n%s\n" %test_complete)
	return test_complete

def ss_test22(snap_name,clone_name,vm_amount):        
		#Create multiple maxta clones, remove existing disk#1 and add a new disk to every maxta clone
		mylist = find_vms(clone_name)		
		if len(mylist) == int(0):			
			# Create maxta snapshot
			create_maxta_snapshot(guest_name,snap_name,mgmtip_port,mgmt_user,mgmt_pwd,intrface='ens192')
			# Create multiple maxta clones
			clone_failcount = 0
			disk_failcount = 0
			hostcount = len(host_list)
			count = 0
			vmcount = 1
			while (vmcount <= vm_amount) and (count <= hostcount):
					vm_name = '%s%s' %(clone_name,vmcount)
					myhost = host_list[count]
					logger1.info("Creating maxta clone '%s' from snapshot '%s'" %(vm_name,snap_name))
					test1 = create_maxta_clone(snap_name,vm_name,mgmtip_port,mgmt_user,mgmt_pwd,dc,myhost,datastore,intrface='ens192')
					if test1 == "FAIL":
						clone_failcount += 1
					remove_disk_vm(vm_name,unitNumber=1,wait=True)
					time.sleep(10)
					test2 = add_disk(vm_name,disk_amount)
					if test2 == "FAIL":
						disk_failcount += 1
					rebootGuest(vm_name)
					count += 1
					vmcount += 1
					if (count == hostcount) and (vmcount <= vm_amount):
							#Reset the count to 0
							count = 0
			if (clone_failcount >= 1) & (disk_failcount == 0):
				logger2.error("One or more clones failed to create...")
				logger2.info("ss_test22 : FAIL")
			elif (clone_failcount == 0) & (disk_failcount >= 1):
				logger2.error("Failed to add disks to one or more VMs...")
				logger2.info("ss_test22 : FAIL")
			elif (clone_failcount >= 1) & (disk_failcount >= 1):
				logger2.error("Failed to create oen or more clones and add disks to them...")
				logger2.info("ss_test22 : FAIL")
			else:
				logger2.info("All the clones created and disk were added successfully...")
				logger2.info("ss_test22 : PASS")
		else:
			disk_failcount = 0
			logger1.info(mylist)
			for vm_name in mylist:
				remove_disk_vm(vm_name,unitNumber=1,wait=True)
				time.sleep(10)
				test2 = add_disk(vm_name,disk_amount)
				if test2 == "FAIL":
					disk_failcount += 1
				rebootGuest(vm_name)
			if (disk_failcount == 0):
				logger2.error("All disk were added successfully...")
				logger2.info("ss_test22 : PASS")
			if (disk_failcount >= 1):
				logger2.error("Failed to add disks to one or more VMs...")
				logger2.info("ss_test22 : FAIL")


def cl_test23(guest_name,disk_amount):
	# Add multiple vdisks to the existing VMs
	disk_failcount = 0
	vm_list = find_vms(guest_name)
	# Add disk operation				       
	logger1.info(vm_list)				
	while len(vm_list) == 0:                        
			logger1.info("Retrying Finding VMs with "+ guest_name + " prefix/suffix")
			vm_list = find_vms(guest_name)
			logger1.info(vm_list)
			time.sleep(20)
	for vm in vm_list:
			logger1.info("Trying to add disk to '%s'" %vm)
			test = add_disk(vm,disk_amount)
			if test == 'FAIL':
				disk_failcount += 1			
			vm1 = find_vm(vm)      
			status = vm1.is_powered_on()    
			while status != True:
					status = vm1.is_powered_on()
					logger1.info("Waiting for '%s' to power on" %vm)
					time.sleep(10)	
			rebootGuest(vm)
	if disk_failcount >= 1:
		logger2.error("Failed to add one or more disks to the guest VM...")
		logger2.info("cl_test23 : FAIL")
	else:
		logger2.error("Successfully added all the disks to guest VM...")
		logger2.info("cl_test23 : PASS")


def ct_test24(testcase):
		# Crash test on zk-leader node by powering off maxta VM
		name = datastore
		vm_list = find_vms(name)
		test_complete = "Test completed, Please check the logs for any issues..."
		anlyz_file = "maxta_log_analyzer.log"
		pre_file = "staleInode_pre.log"
		post_file = "staleInode_post.log"
		pre_anlyz_file = "Analyzer_pre.log"
		post_anlyz_file = "Analyzer_post.log"
		testcase = str(testcase)
		dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+testcase+check_pf
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
		cmd4 = "cat /var/log/zookeeper/zookeeper.log | grep -iE 'TOOK' | awk '{print $8}'"
		
		logger1.info("Maxta VMs found: %s" %vm_list)
		(outdata1, rc1) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
		with open(pre_file_dest, 'w') as file:
			for item in outdata1:
				file.write("%s\n" % item)
		maxta_log_analyzer(testcase=testcase)
		shutil.move(anlyz_file_src, pre_anlyz_file_dest)
		logger1.info("Renaming '%s' to '%s'" %(anlyz_file,pre_anlyz_file))
		time.sleep(10)
		count = 0
		while count <= iterations:
			for vm in vm_list:		
				vm_ip = get_ipaddr(vm)
				print vm_ip
				(outdata5, rc5) = ssh_cmd(cmd4,vm_ip,mgmt_user,mgmt_pwd)
				print outdata5[0]
				if outdata5[0] == "LEADING":
					failed_msg = "Somthing wrong!! with maxta storage after crashing %s" %vm
					passed_msg = "Everything looks good on %s!!, moving to next iteration" %vm					
					logger1.info("Powering off maxta VM: %s\n" %vm)
					powerOffGuest(vm)
					time.sleep(300)
					logger1.info("Powering on maxta VM: %s\n" %vm)
					powerOnGuest(vm)
					time.sleep(180)
					(outdata2, rc2) = ssh_cmd(cmd1,mgmtip_port,mgmt_user,mgmt_pwd)
					with open(post_file_dest, 'w') as file:
						for item in outdata2:
							file.write("%s\n" % item)
					maxta_log_analyzer(testcase=testcase)
					shutil.move(anlyz_file_src, post_anlyz_file_dest)
					logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
					time.sleep(10)
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
						logger1.info("Renaming '%s' to '%s'" %(anlyz_file,post_anlyz_file))
						(outdata3, rc3) = diff_file(cmd2)
						if rc3 == 1:
							logger1.error("\n\n%s\n" %failed_msg)
							return failed_msg
						else:
							logger1.info("\n\n%s\n" %passed_msg)
							logger1.info("="*150+"\n")								
							subject = "Crash test ct_test15 on %s" %cluster
							send_mail(username,password,my_recipients,subject,passed_msg)
				else:
					logger1.info("Node '%s' is FOLLOWING the leader" %vm)
			count += 1		
		logger1.info("\n\n%s\n" %test_complete)
		return test_complete
		
		
		
		



### MAIN SECTION TO EXECUTE TEST CASES ###         

logger1.info("Testcases you have selected to run: " + str(testid)+ "\n")
for test in testid:
		test1_snap_name = 'ss_test1_snap'
		test2_snap_name = 'ss_test2_snap'
		test3_snap_name = 'ss_test3_snap'
		test3_clone_name = 'ss_test3_clone'
		if test == '0':
				logger1.info("#################################")
				logger1.info("Initializing Maxta Logs Analyzer")
				logger1.info("#################################")
				maxta_log_analyzer(download=True,testcase=None,rand_string=None)
		elif test == '1':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")				
				ss_test1(guest_name,test1_snap_name,mem=True,quice=False)
		elif test == '2':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")				
				ss_test2(guest_name,test2_snap_name,mem=True,quice=False)
		elif test == '3':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")				
				ss_test3(guest_name,test3_snap_name,test3_clone_name,pwron=True,wait=True)
		elif test == '4':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")
				ss_test4(guest_name,test3_snap_name,test3_clone_name)
		elif test == '5':
				logger1.info("##############################")
				logger1.info("Executing Test vM_test%s" %test)
				logger1.info("##############################")
				vM_test5(guest_name)
		elif test == '6':
				logger1.info("##############################")
				logger1.info("Executing Test cl_test%s" %test)
				logger1.info("##############################")				
				cl_test6(clone_name)
		elif test == '7':
				logger1.info("##############################")
				logger1.info("Executing Test vM_test%s" %test)
				logger1.info("##############################")
				vM_test7(clone_name)
		elif test == '8':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")                
				ss_test8(guest_name,snap_name,snap_amount)
		elif test == '9':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")
				test9_sname = snap_name+"-1"
				test9_cname = 'test%s-clone' %test
				myvm_amount = 3
				ss_test9(test9_sname,test9_cname,myvm_amount)
		elif test == '10':
				logger1.info("##############################")
				logger1.info("Executing Test vM_test%s" %test)
				logger1.info("##############################")
				vM_test10(guest_name,iso_ds,wait=True)
		elif test == '11':
				logger1.info("##############################")
				logger1.info("Executing Test vM_test%s" %test)
				logger1.info("##############################")
				vM_test11(guest_name,iso_ds,wait=True)
		elif test == '12':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")
				ss_test12(guest_name)
		elif test == '13':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")
				ss_test13(guest_name)
		elif test == '14':
				logger1.info("##############################")
				logger1.info("Executing Test sb_test%s" %test)
				logger1.info("##############################")                
				sb_test14(testcase='sb_test%s' %test)
		elif test == '15':
				logger1.info("##############################")
				logger1.info("Executing Test ct_test%s" %test)
				logger1.info("##############################")  				                             
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ct_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ct_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]
				subject = "Crash test ct_test%s on %s" %(test,cluster)
				message = ct_test15(testcase)
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ct_test%s : FAIL" %test)
				else:
					logger2.info("ct_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)			
		elif test == '16':
				logger1.info("##############################")
				logger1.info("Executing Test ct_test%s" %test)
				logger1.info("##############################")
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ct_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ct_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]
				subject = "Crash test ct_test%s on %s" %(test,cluster)
				message = ct_test16(testcase)
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ct_test%s : FAIL" %test)
				else:
					logger2.info("ct_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)
		elif test == '17':
				logger1.info("##############################")
				logger1.info("Executing Test vM_test%s" %test)
				logger1.info("##############################")
				vM_test17(clone_name)
		elif test == '18':
				logger1.info("##############################")
				logger1.info("Executing Test ha_test%s" %test)
				logger1.info("##############################")
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ha_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ha_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]
				subject = "Crash test ha_test%s on %s" %(test,cluster)
				message = ha_test18(clone_name,testcase)				
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ha_test%s : FAIL" %test)
				else:
					logger2.info("ha_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)
		elif test == '19':
				logger1.info("##############################")
				logger1.info("Executing Test ha_test%s" %test)
				logger1.info("##############################")
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ha_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ha_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]				
				subject = "Crash test ha_test%s on %s" %(test,cluster)
				message = ha_test19(clone_name,testcase)
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ha_test%s : FAIL" %test)
				else:
					logger2.info("ha_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)
		elif test == '20':
				logger1.info("##############################")
				logger1.info("Executing Test ha_test%s" %test)
				logger1.info("##############################")
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ha_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ha_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]
				subject = "Crash test ha_test%s on %s" %(test,cluster)
				message = ha_test20(clone_name,testcase)
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ha_test%s : FAIL" %test)
				else:
					logger2.info("ha_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)
		elif test == '21':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ss_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ss_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]
				subject = "Crash test ss_test%s on %s" %(test,cluster)			
				vm_name = 'test21_clone' 
				message = ss_test21(vm_name,testcase)				
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ss_test%s : FAIL" %test)
				else:
					logger2.info("ss_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)
		elif test == '22':
				logger1.info("##############################")
				logger1.info("Executing Test ss_test%s" %test)
				logger1.info("##############################")                
				test22_cname = 'test22-Clone'
				ss_test22(snap_name,test22_cname,vm_amount)
		elif test == '23':
				logger1.info("##############################")
				logger1.info("Executing Test cl_test%s" %test)
				logger1.info("##############################")
				cl_test23(guest_name,disk_amount)
		elif test == '24':
				logger1.info("##############################")
				logger1.info("Executing Test ct_test%s" %test)
				logger1.info("##############################")
				Analyzer_log = "Analyzer_post.log"
				testcase =  "ct_test%s" %test
				dest_dir = os.getcwd()+check_pf+"Logs"+check_pf+"ct_test"+test+check_pf
				attachments = ['vmware-auto.log', 'Test-Report.log', dest_dir+Analyzer_log]
				subject = "Crash test ct_test%s on %s" %(test,cluster)
				message = ct_test24(testcase)
				if re.match('Somthing wrong!!', message):
					gen_support_bundle(testcase=testcase)
					logger1.info("\n\nDownloading logs complete, please check the logs.\n")
					logger2.error(message)
					logger2.info("ct_test%s : FAIL" %test)
				else:
					logger2.info("ct_test%s : PASS" %test)
				send_mail(username,password,my_recipients,subject,message,attachments)
		else:
				logger1.error("Please specify the testid's in config file")

#disconnect from vCenter
#host_con.disconnect()
