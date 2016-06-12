#!/usr/bin/env python
# Author: Manindra T
# Date: 26th-March-2016

from pysphere.resources import VimService_services as VI
from pysphere import MORTypes, VIServer, VITask, VIProperty, VIMor, VIException, VIApiException, FaultTypes
from pysphere.vi_virtual_machine import VIVirtualMachine
import sys, os, re, getpass, subprocess, atexit
from ConfigParser import SafeConfigParser
from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect, Disconnect
import time 
import logging
import StringIO
import paramiko
import ssl
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

if hasattr(ssl, '_create_unverified_context'):
	ssl._create_default_https_context = ssl._create_unverified_context

# Parsing Config from vmware-auto.cfg file
parser = SafeConfigParser()
parser.read('vmware-auto.cfg')

# Properties to be used for tests
vc_ip = parser.get('vcenter', 'vc_ip')  # vCenter ip address to connect
vc_user = parser.get('vcenter', 'vc_user')    # vCenter username
vc_pwd = parser.get('vcenter', 'vc_pwd')     # vCenter password
cluster = parser.get('host', 'cluster')     # Specify the cluster name
dc = parser.get('host', 'dc')        # Specify the name of the Datacenter to be used
	

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

	# We have to get the stdout & stderr here, otherwise we do not have any if 
	# we get them at the end of this function.
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


def remote_ssh_cmd(cmd,mgmtip_port,mgmt_user,mgmt_pwd):
	logger.info("Initialize SSH client to Server '%s' ...", mgmtip_port)

	if ':' in mgmtip_port:
		vdlist = mgmtip_port.split(':')
		mgmtip = vdlist[0]
		portnum = vdlist[1]
		logger.info("MgmtIP='%s' MgmtPort='%s'", mgmtip, portnum)
		sshclient = createSshClient(mgmtip, mgmt_user, mgmt_pwd, portnum)
	else:
		mgmtip = mgmtip_port
		logger.info("MgmtIP='%s'", mgmtip)
		sshclient = createSshClient(mgmtip, mgmt_user, mgmt_pwd)
	
	(rc, outdata, stderr) = executeRemote(sshclient, cmd, False)
	#logger.info("ret stdout '%s'", outdata)
	return (outdata, rc)
	if rc != 0 and rc != None:
		msg = "FAIL: cmd '%s' returns retcode %d." % (cmd, rc)
		exitprog(msg, -1)
	
	sshclient.close()
	logger.info("Just Closed Mgmt SSH Clients.")

def scp_file(mgmtip_port,mgmt_user,mgmt_pwd,source,destination,copyType):
	logger.info("Initialize SCP client to Server '%s' ...", mgmtip_port)
	scpclient = createScpClient(mgmtip_port, mgmt_user, mgmt_pwd)

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
# setting up logging to file
def setup_logger(logger_name, log_file, level=logging.DEBUG, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s'):
	l = logging.getLogger(logger_name)	
	formatter = logging.Formatter(format)
	fileHandler = logging.FileHandler(log_file, mode='a')
	fileHandler.setFormatter(formatter)
	streamformat = '%(name)-12s: %(levelname)-8s %(message)s'
	streamformatter = logging.Formatter(streamformat)
	streamHandler = logging.StreamHandler()
	streamHandler.setLevel(logging.INFO)
	streamHandler.setFormatter(streamformatter)
	l.setLevel(level)
	l.addHandler(fileHandler)
	l.addHandler(streamHandler)

curdir = os.getcwd()
setup_logger('MasterLog', 'vmware-auto.log')
setup_logger('ControlLog', 'vmware-auto.log')
setup_logger('Result', 'Test-Report.log')
logger = logging.getLogger('MasterLog')
logger1 = logging.getLogger('ControlLog')
logger2 = logging.getLogger('Result')


# Code for Connecting to vCenter 
#==============================================================================================================
def connectToHost(vc_ip,vc_user,vc_pwd):
	#create server object
	s=VIServer()
	#connect to the vc
	try:
		s.connect(vc_ip,vc_user,vc_pwd)				
		return s
	except VIApiException, err:
		logger.error("Cannot connect to vCenter: "+vc_ip+" error message: %s" %err)

def smartconnect(vc_ip,vc_user,vc_pwd):
		#create server object
		try:
				si = SmartConnect(host=vc_ip,user=vc_user,pwd=vc_pwd)
				session_id = si.content.sessionManager.currentSession
				logger.debug("current pyVmomi session id: %s, user : %s" %(session_id.key,session_id.userName))
				return si, session_id.key, session_id.userName                     
		except vmodl.MethodFault as e:      
				logger.error("Cannot connect to vCenter: "+vc_ip+" error message: %s" %e.msg)
		
#===============================================================================================================
host_con = connectToHost(vc_ip,vc_user,vc_pwd)
smart_con, session_key, session_user = smartconnect(vc_ip,vc_user,vc_pwd)
#===============================================================================================================
def find_vm(name):
	global host_con
	try:				
		vm = host_con.get_vm_by_name(name)
		logger.debug("vm debug status is: "+ str(vm))
		if vm == None:                
			logger.error("Hit an exception and failed to get VM object")				
			logger.info("find_vm: Reconnecting to VIServer...")		
			host_con = connectToHost(vc_ip,vc_user,vc_pwd)
			vm = host_con.get_vm_by_name(name)
			return vm
		else:
			return vm     
	except VIException, e:
				logger.error(e)

#===============================================================================================================
def find_vms(name):
		global host_con		
		list_clone_paths = []
		list_clones = []				
		logger1.info("Finding VMs with prefix : %s" %name)
		a = host_con.get_registered_vms(cluster=cluster,datacenter=dc)        
		for path in a:                
			list_clone_paths.append(path)
		for ipath in list_clone_paths:
			b = host_con.get_vm_by_path(ipath)
			c = b.get_property('name')
			if re.match('%s' % name, c):
				list_clones.append(c)
		logger.debug("list of VMs avilable: %s" %list_clones)							       
		if len(list_clones) == 0:
			logger.info("find_vms: Reconnecting to VIServer...")			
			#host_con.disconnect()
			host_con = connectToHost(vc_ip,vc_user,vc_pwd)     
			a = host_con.get_registered_vms(cluster=cluster,datacenter=dc)        
			for path in a:                
				list_clone_paths.append(path)
			for ipath in list_clone_paths:
				b = host_con.get_vm_by_path(ipath)
				c = b.get_property('name')
				if re.match('%s' % name, c):
						list_clones.append(c)
		list_clones = sorted(list_clones)		
		return list_clones

#================================================================================================================
def ping(ip):
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

#================================================================================================================
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
			
#================================================================================================================
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

#================================================================================================================
def get_ipaddr(vm_name):
	global smart_con, session_key, session_user
	
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
   
   
#===============================================================================================================			
def createGuest(dc,esx_host,guest_name,guest_ver,guest_mem,guest_cpu,guest_id,guest_disk_gb,datastore,guest_network,guest_enterbios,iso_ds,iso_path):
	#get dc MOR from list
	dc_list=[k for k,v in host_con.get_datacenters().items() if v==dc]
	if dc_list:
		dc_mor=dc_list[0]
	else:
		#host_con.disconnect()
		logger.error ("Cannot find dc: "+dc)
	dc_props=VIProperty(host_con, dc_mor)
	#get vmFolder
	vmf_mor = dc_props.vmFolder._obj
	#get hostfolder MOR
	hf_mor=dc_props.hostFolder._obj
	#get computer resources MORs
	cr_mors=host_con._retrieve_properties_traversal(property_names=['name','host'],from_node=hf_mor,obj_type='ComputeResource')
	#get host MOR
	try:
		host_mor=[k for k,v in host_con.get_hosts().items() if v==esx_host][0]
	except IndexError, e:
		#host_con.disconnect()
		logger.error("Cannot find host: "+esx_host)
	#get computer resource MOR for host
	cr_mor=None
	for cr in cr_mors:
		if cr_mor:
			break
		for p in cr.PropSet:
			if p.Name=="host":
				for h in p.Val.get_element_ManagedObjectReference():
					if h==host_mor:
						 cr_mor=cr.Obj
						 break
				if cr_mor:
					break
	cr_props=VIProperty(host_con,cr_mor)
	#get resource pool MOR
	rp_mor=cr_props.resourcePool._obj
 
	#build guest properties
	#get config target
	request=VI.QueryConfigTargetRequestMsg()
	_this=request.new__this(cr_props.environmentBrowser._obj)
	_this.set_attribute_type(cr_props.environmentBrowser._obj.get_attribute_type())
	request.set_element__this(_this)
	h=request.new_host(host_mor)
	h.set_attribute_type(host_mor.get_attribute_type())
	request.set_element_host(h)
	config_target=host_con._proxy.QueryConfigTarget(request)._returnval
	#get default devices
	request=VI.QueryConfigOptionRequestMsg()
	_this=request.new__this(cr_props.environmentBrowser._obj)
	_this.set_attribute_type(cr_props.environmentBrowser._obj.get_attribute_type())
	request.set_element__this(_this)
	h=request.new_host(host_mor)
	h.set_attribute_type(host_mor.get_attribute_type())
	request.set_element_host(h)
	config_option=host_con._proxy.QueryConfigOption(request)._returnval
	defaul_devs=config_option.DefaultDevice
	#get network names
	if guest_network:
		net_name=guest_network
	else:
		for net in config_target.Network:
			if net.Network.Accessible:
				net_name = net.Network.Name
	#get ds
	ds_target = None
	for d in config_target.Datastore:
		if d.Datastore.Accessible and (datastore and d.Datastore.Name==datastore) or (not datastore):
			ds_target=d.Datastore.Datastore
			datastore=d.Datastore.Name
			break
	if not ds_target:
		#host_con.disconnect()
		logger.error("Cannot find datastore: "+datastore)
	ds_vol_name="[%s]" % datastore
 
	#get ios_ds
	iso_target = None
	for d in config_target.Datastore:
		if d.Datastore.Accessible and (iso_ds and d.Datastore.Name==iso_ds) or (not iso_ds):
			iso_target=d.Datastore.Datastore
			iso_ds=d.Datastore.Name
			break
	if not iso_target:
		#host_con.disconnect()
		logger.error("Cannot find datastore: "+iso_ds)
	ds_iso_vol="[%s]" % iso_ds
 
 
	#create task request
	create_vm_request=VI.CreateVM_TaskRequestMsg()
	config=create_vm_request.new_config()
	#set location of vmx
	vm_files=config.new_files()
	vm_files.set_element_vmPathName(ds_vol_name)
	config.set_element_files(vm_files)
	if guest_enterbios:
		#set boot parameters
		vmboot=config.new_bootOptions()
		vmboot.set_element_enterBIOSSetup(True)
		config.set_element_bootOptions(vmboot)
	#set general parameters
	config.set_element_version(guest_ver)
	config.set_element_name(guest_name)
	config.set_element_memoryMB(guest_mem)
	config.set_element_memoryHotAddEnabled(True)
	config.set_element_numCPUs(guest_cpu)
	config.set_element_guestId(guest_id)
	config.set_element_cpuHotAddEnabled(True)
 
	#create devices
	devices = []
	#add controller to devices
	disk_ctrl_key=1
	scsi_ctrl_spec=config.new_deviceChange()
	scsi_ctrl_spec.set_element_operation('add')
	scsi_ctrl = VI.ns0.VirtualLsiLogicSASController_Def("scsi_ctrl").pyclass()
	scsi_ctrl.set_element_busNumber(0)
	scsi_ctrl.set_element_key(disk_ctrl_key)
	scsi_ctrl.set_element_sharedBus("noSharing")
	scsi_ctrl_spec.set_element_device(scsi_ctrl)
	devices.append(scsi_ctrl_spec)
	#find ide controller
	ide_ctlr = None
	for dev in defaul_devs:
		if dev.typecode.type[1] == "VirtualIDEController":
			ide_ctlr = dev
	#add cdrom
	if ide_ctlr:
		cd_spec = config.new_deviceChange()
		cd_spec.set_element_operation('add')
		cd_ctrl = VI.ns0.VirtualCdrom_Def("cd_ctrl").pyclass()
		cd_device_backing =VI.ns0.VirtualCdromIsoBackingInfo_Def("cd_device_backing").pyclass()
		ds_ref = cd_device_backing.new_datastore(ds_target)
		ds_ref.set_attribute_type(ds_target.get_attribute_type())
		cd_device_backing.set_element_datastore(ds_ref) 
		cd_device_backing.set_element_fileName("%s %s" % (ds_iso_vol,iso_path))
		cd_ctrl.set_element_backing(cd_device_backing)
		cd_ctrl.set_element_key(20)
		cd_ctrl.set_element_controllerKey(ide_ctlr.get_element_key())
		cd_ctrl.set_element_unitNumber(0)
		cd_spec.set_element_device(cd_ctrl)
		devices.append(cd_spec)
	#add disk
	disk_spec=config.new_deviceChange()
	disk_spec.set_element_fileOperation("create")
	disk_spec.set_element_operation("add")
	disk_ctlr=VI.ns0.VirtualDisk_Def("disk_ctlr").pyclass()
	disk_backing=VI.ns0.VirtualDiskFlatVer2BackingInfo_Def("disk_backing").pyclass()
	disk_backing.set_element_fileName(ds_vol_name)
	disk_backing.set_element_diskMode("persistent")
	disk_ctlr.set_element_key(0)
	disk_ctlr.set_element_controllerKey(disk_ctrl_key)
	disk_ctlr.set_element_unitNumber(0)
	disk_ctlr.set_element_backing(disk_backing)
	guest_disk_size=guest_disk_gb*1024*1024
	disk_ctlr.set_element_capacityInKB(guest_disk_size)
	disk_spec.set_element_device(disk_ctlr)
	devices.append(disk_spec)
	#add a network controller
	nic_spec = config.new_deviceChange()
	if net_name:
		nic_spec.set_element_operation("add")
		nic_ctlr = VI.ns0.VirtualVmxnet3_Def("nic_ctlr").pyclass()
		nic_backing = VI.ns0.VirtualEthernetCardNetworkBackingInfo_Def("nic_backing").pyclass()
		nic_backing.set_element_deviceName(net_name)
		nic_ctlr.set_element_addressType("generated")
		nic_ctlr.set_element_backing(nic_backing)
		nic_ctlr.set_element_key(4)
		nic_spec.set_element_device(nic_ctlr)
		devices.append(nic_spec)
 
	#create vm request
	config.set_element_deviceChange(devices)
	create_vm_request.set_element_config(config)
	new_vmf_mor=create_vm_request.new__this(vmf_mor)
	new_vmf_mor.set_attribute_type(vmf_mor.get_attribute_type())
	new_rp_mor=create_vm_request.new_pool(rp_mor)
	new_rp_mor.set_attribute_type(rp_mor.get_attribute_type())
	new_host_mor=create_vm_request.new_host(host_mor)
	new_host_mor.set_attribute_type(host_mor.get_attribute_type())
	create_vm_request.set_element__this(new_vmf_mor)
	create_vm_request.set_element_pool(new_rp_mor)
	create_vm_request.set_element_host(new_host_mor)
 
	#finally actually create the guest :)
	task_mor=host_con._proxy.CreateVM_Task(create_vm_request)._returnval
	task=VITask(task_mor,host_con)
	task.wait_for_state([task.STATE_SUCCESS,task.STATE_ERROR])
	if task.get_state()==task.STATE_ERROR:
		logger.error("Cannot create guest: " + task.get_error_message())
		return "FAIL"
	else:
		logger.info("Successfully created guest: " + '"' + guest_name + '"')
		return "PASS"
		
#==========================================================================================================		
def getMac(guest_name):
	vm=host_con.get_vm_by_name(guest_name)
	net = vm.get_property('net', from_cache=False)
	if net:
		for interface in net:
			mac = interface.get('mac_address', None)
			if mac:
				return mac
 
	for v in vm.get_property("devices").values():
		if v.get('macAddress'):            
			return v.get('macAddress')    
	
#===========================================================================================================			
def powerOnGuest(guest_name,sync_run=True):
	global host_con
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	logger.debug("src_vm : %s" %src_vm)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("powerOn: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm
	logger.info('Virtual Machine %s found' % guest_name)
	vm_status = src_vm.get_status()
	if vm_status == "POWERED ON":
		logger.info("%s is already powered on" %guest_name)		
	else:
		logger.info("Powering on vm %s" %guest_name)
		src_vm.power_on(sync_run)
		if sync_run == False:
			time.sleep(30)
			vm_status2 = src_vm.is_powering_on()
			logger.debug("Is vm powering on: %s" %vm_status2)
			count = 0
			while count < 5: 			
				time.sleep(60)
				question = src_vm.is_blocked_on_msg()
				if question:
					logger.warning("VM %s got blocked with virtual machine question" %guest_name)
					q = src_vm.get_question()
					logger.info("virtual machine question is answered...")
					q.answer()
					break
				else:
					logger.info("Waiting 60 sec's for VM to power on...")
				count += 1

#=============================================================================================================
def powerOffGuest(guest_name,sync_run=True):
	global host_con
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	logger.debug("src_vm : %s" %src_vm)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("powerOff: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm		
	logger.info('Virtual Machine %s found' % guest_name)
	vm_status = src_vm.get_status()
	if vm_status == "POWERED OFF":
		logger.info("%s is already powered off" %guest_name)		
	else:
		logger.info("Powering off vm %s" %guest_name)
		src_vm.power_off(sync_run)

#=================================================================================================================
def resetGuest(guest_name,sync_run=True):
	global host_con
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("reset: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm	
	logger.info('Virtual Machine %s found' % guest_name)
	vm_status = src_vm.get_status()
	if vm_status == "POWERED OFF":
		logger.info("%s is already powered off" %guest_name)		
	else:
		logger.info("Resetting vm %s" %guest_name)
		src_vm.reset(sync_run)        
	
#===================================================================================================================		
def suspendGuest(guest_name,sync_run=True):
	global host_con
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("suspend: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm	
	logger.info('Virtual Machine %s found' % guest_name)
	vm_status = src_vm.get_status()
	if vm_status == "SUSPENDED":
		logger.info("%s is already suspended" %guest_name)		
	else:
		logger.info("Suspending vm %s" %guest_name)
		src_vm.suspend(sync_run)
		
#==============================================================================================================
def shutdownGuest(guest_name):
	global host_con
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("shutdown: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm	
	logger.info('Virtual Machine %s found' % guest_name)
	vm_status = src_vm.get_status()
	if vm_status == "POWERED OFF":
		logger.info("%s is already shutdown" %guest_name)		
	else:
		vmtools_status = src_vm.get_tools_status()
		logger.info("Shutting down vm %s" %guest_name)
		if vmtools_status in ['RUNNING', 'RUNNING OLD']:
			logger.info("VMware Tools status: "+vmtools_status)	
			src_vm.shutdown_guest()
			logger.info("Shutdown Initiated on vm: %s" %guest_name)
		else:
			logger.info("Waiting 60 seconds for VMware Tools to come up...")
			count = 0
			while count < 5:
				try:				
					src_vm.wait_for_tools(timeout=60)
				except VIException, e:					
					logger.error(e)
					logger.warning("Waiting another 60 seconds for VMware Tools to come up...")
				vmtools_status = src_vm.get_tools_status()
				if vmtools_status in ['RUNNING', 'RUNNING OLD']:					
					break								
				count += 1
			logger.info("VMware Tools status: "+vmtools_status)
			time.sleep(30)
			src_vm.shutdown_guest()
			logger.info("Shutdown Initiated on vm: %s" %guest_name)     
		
#==================================================================================================================
def rebootGuest(guest_name):
	global host_con
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("reboot: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm	
	logger.info('Virtual Machine %s found' % guest_name)
	vm_status = src_vm.get_status()
	if vm_status == "POWERED OFF":
		logger.info("%s is powered off" %guest_name)		
	else:
		vmtools_status = src_vm.get_tools_status()
		logger.info("Rebooting vm %s" %guest_name)		
		if vmtools_status in ['RUNNING', 'RUNNING OLD']:
			logger.info("VMware Tools status: "+vmtools_status)			
			src_vm.reboot_guest()
			logger.info("Reboot Initiated on vm: %s" %guest_name)
		else:
			logger.info("Waiting 60 seconds for VMware Tools to come up...")
			count = 0
			while count < 5:
				try:				
					src_vm.wait_for_tools(timeout=60)
				except VIException, e:					
					logger.error(e)
					logger.warning("Waiting another 60 seconds for VMware Tools to come up...")
				vmtools_status = src_vm.get_tools_status()
				if vmtools_status in ['RUNNING', 'RUNNING OLD']:					
					break								
				count += 1
			logger.info("VMware Tools status: "+vmtools_status)
			time.sleep(30)
			src_vm.reboot_guest()
			logger.info("Reboot Initiated on vm: %s" %guest_name)

#================================================================================================================
def add_scsi_crtlr(guest_name,ctrlr_key,bus_num,wait=True):	
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		
	request = VI.ReconfigVM_TaskRequestMsg()
	_this = request.new__this(src_vm._mor)
	_this.set_attribute_type(src_vm._mor.get_attribute_type())
	request.set_element__this(_this)
		
	spec = request.new_spec()

	dc = spec.new_deviceChange()
	dc.Operation = "add"
	disk_ctrl_key=ctrlr_key
	scsi_ctrl = VI.ns0.VirtualLsiLogicSASController_Def("scsi_ctrl").pyclass()
	scsi_ctrl.set_element_busNumber(bus_num)
	scsi_ctrl.set_element_key(disk_ctrl_key)
	scsi_ctrl.set_element_sharedBus("noSharing")
				
	dc.Device = scsi_ctrl

	spec.DeviceChange = [dc]
	request.Spec = spec

	task = host_con._proxy.ReconfigVM_Task(request)._returnval
	vi_task = VITask(task, host_con)

	if wait == True:
			status = vi_task.wait_for_state(['success', 'error'])
			if status == 'error':
				logger.error("Error configuring VM: " + vi_task.get_error_message())
				return "FAIL"				
			else:
				logger.info("Successfully added new SCSI controller to VM " + '"' + guest_name + '"')
				return "PASS"                
	else:
			status = vi_task.get_state()
			if status == 'error':
				logger.error("Error configuring VM: " + vi_task.get_error_message())
				return "FAIL"				
			else:
				logger.info("Successfully added new SCSI controller to VM " + '"' + guest_name + '"')
				return "PASS"

#==================================================================================================================
def add_disk_vm(guest_name,datastore,guest_disk_gb,wait=True):	
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)

	vm_prop = src_vm.get_properties()			
	#print "adding disk to %s" %devid[scsictrl_list[1]]
	dev = vm_prop['devices']	
	hdd_list = []
	regex1 = re.compile('.*Hard disk.*')
	disk_name = {key: m.group(0) for key, value in dev.iteritems() for m in [regex1.search(value['label'])] if m}
	for key, value in disk_name.iteritems():
		hdd_list.append(key)
	hdd_list = sorted(hdd_list)

	scsictrl_list = []
	regex2 = re.compile('.*SCSI controller.*')	
	devid = {key: m.group(0) for key, value in dev.iteritems() for m in [regex2.search(value['label'])] if m}
	for key, value in devid.iteritems():
		scsictrl_list.append(key)		
	scsictrl_list = sorted(scsictrl_list)

	if len(hdd_list) == 15*len(scsictrl_list):
		unitNum = 0	
	elif len(hdd_list) <= 7:
		unitNum = len(hdd_list)
		if unitNum == 7:
			unitNum += 1		
	elif (len(hdd_list) > 7) and (len(hdd_list) <= 15):
		unitNum = len(hdd_list) + 1
	elif len(hdd_list) >= 16:
		unitNum = (len(hdd_list) - (15*(len(scsictrl_list) - 1)))
		if unitNum >= 7 and unitNum < 15 :
			unitNum += 1		
	else:
		print "Unit number is invalid"	

	ctrlr_key = scsictrl_list[-1:]
	ctrlr_key = ctrlr_key[0]	
	
	if len(hdd_list) == 15*len(scsictrl_list):				
		ctrlr_key += 1
		if ctrlr_key == 1004:
			logger.info("Maximun Controllers reached, Can not create more than 4 controllers")			
		bus_num = len(scsictrl_list)
		logger.info("Maximum devices exeeded on current SCSI controller, Creating new SCSI controller %s" %bus_num) 
		add_scsi_crtlr(guest_name,ctrlr_key,bus_num,wait=True)
		# Resetting unit number to 0
		unitNum = 0	
	
	request = VI.ReconfigVM_TaskRequestMsg()
	_this = request.new__this(src_vm._mor)
	_this.set_attribute_type(src_vm._mor.get_attribute_type())
	request.set_element__this(_this)
		
	spec = request.new_spec()

	dc = spec.new_deviceChange()
	dc.Operation = "add"
	dc.FileOperation = "create"

	hd = VI.ns0.VirtualDisk_Def("hd").pyclass()
	hd.Key = -100
	logger.debug("using unitnum %s" %unitNum)
	hd.UnitNumber = unitNum
	hd.CapacityInKB = guest_disk_gb*1024*1024
	logger.debug("using controller key %s" %ctrlr_key)
	hd.ControllerKey = ctrlr_key

	backing = VI.ns0.VirtualDiskFlatVer2BackingInfo_Def("backing").pyclass()
	backing.FileName = "[%s]" % datastore
	backing.DiskMode = "persistent"
	backing.Split = False
	backing.WriteThrough = False
	backing.ThinProvisioned = True
	backing.EagerlyScrub = False
	hd.Backing = backing

	dc.Device = hd

	spec.DeviceChange = [dc]
	request.Spec = spec

	task = host_con._proxy.ReconfigVM_Task(request)._returnval
	vi_task = VITask(task, host_con)

	if wait == True:
			status = vi_task.wait_for_state(['success', 'error'])
			if status == 'error':
				logger.error("Error configuring VM: " + vi_task.get_error_message())
				return "FAIL" 				
			else:
				logger.info("Successfully added new disk to VM " + '"' + guest_name + '"')
				return "PASS"                 
	else:
			status = vi_task.get_state()
			if status == 'error':
				logger.error("Error configuring VM: " + vi_task.get_error_message())
				return "FAIL" 				
			else:
				logger.info("Successfully added new disk to VM " + '"' + guest_name + '"')
				return "PASS" 
		
	### This is the Alternate section of wait operation ###    
	'''status = vi_task.wait_for_state([vi_task.STATE_SUCCESS, vi_task.STATE_ERROR])
	if status == vi_task.STATE_ERROR:
		logger.error("Error configuring VM:" + vi_task.get_error_message())
	else:
		logger.info("Successfully added new disk to VM " + '"' + guest_name + '"')'''

#==========================================================================================================================
def remove_disk_vm(guest_name,unitNumber=1,wait=True):
	# Verify the VM exists
	logger.info('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		

	if unitNumber < 1:
		logger.warning("You have selected the boot disk, Please specify 'unitNumber' greater than 0")
	else:
		UNIT_NUMBER = unitNumber

	dev = [dev for dev in src_vm.properties.config.hardware.device 
		   if dev._type == "VirtualDisk" and dev.unitNumber == UNIT_NUMBER]

	if not dev:
		raise Exception("NO DEVICE FOUND")

	dev = dev[0]._obj

	request = VI.ReconfigVM_TaskRequestMsg()
	_this = request.new__this(src_vm._mor)
	_this.set_attribute_type(src_vm._mor.get_attribute_type())
	request.set_element__this(_this)

	spec = request.new_spec()
	dc = spec.new_deviceChange()
	dc.Operation = "remove"
	dc.Device = dev

	spec.DeviceChange = [dc]
	request.Spec = spec

	task = host_con._proxy.ReconfigVM_Task(request)._returnval
	vi_task = VITask(task, host_con)

	if wait == True:
			status = vi_task.wait_for_state(['success', 'error'])
			if status == 'error':
				logger.error("Error removing hdd from vm: " + vi_task.get_error_message())
				return "FAIL" 				
			else:
				logger.info("Hard drive successfully removed from" + '"' + guest_name + '"')
				return "PASS"                 
	else:
			status = vi_task.get_state()
			if status == 'error':
				logger.error("Error removing hdd from vm: " + vi_task.get_error_message())
				return "FAIL" 				
			else:
				logger.info("Hard drive successfully removed from" + '"' + guest_name + '"')
				return "PASS" 

#==========================================================================================================================
def clone_from_template(template,vm_name,dc,datastore,cluster,vm_folder=None,resource_pool=None,power_on=True,wait=True):
		global smart_con, session_key, session_user		
		def wait_for_task(task):
			""" wait for a vCenter task to finish """
			task_done = False
			while not task_done:
				if task.info.state == 'success':
					logger.info(task.info.result)
					return task.info.state 

				if task.info.state == 'error':
					logger.error("Failed to Deployed VM from template")                    
					#task_done = True
					return task.info.state 

		try:
			session_status = smart_con.content.sessionManager.SessionIsActive(session_key, session_user)
			logger.debug("Current session status : %s" %session_status)
		except vim.fault.NotAuthenticated:
			logger.info("Session Expired, Reconnecting to vCenter...")
			smart_con, session_key, session_user = smartconnect(vc_ip,vc_user,vc_pwd)

		content = smart_con.RetrieveContent()		
		template_obj = get_obj(content, [vim.VirtualMachine], template)				
		 
		if template_obj != None:
			"""
			Clone a VM from a template/VM, datacenter_name, vm_folder, datastore_name
			cluster_name, resource_pool, and power_on are all optional.
			"""

			# if none git the first one
			datacenter = get_obj(content, [vim.Datacenter], dc)
			
			if vm_folder:
				destfolder = get_obj(content, [vim.Folder], vm_folder)
			else:
				destfolder = datacenter.vmFolder                

			if datastore:
				datastore = get_obj(content, [vim.Datastore], datastore)
			else:
				datastore = get_obj(
					content, [vim.Datastore], template.datastore[0].info.name)

			# if None, get the first one
			cluster = get_obj(content, [vim.ClusterComputeResource], cluster)

			if resource_pool:
				resource_pool = get_obj(content, [vim.ResourcePool], resource_pool)
			else:
				resource_pool = cluster.resourcePool

			# set relospec
			relospec = vim.vm.RelocateSpec()
			relospec.datastore = datastore
			relospec.pool = resource_pool

			clonespec = vim.vm.CloneSpec()
			clonespec.location = relospec
			clonespec.powerOn = power_on

			logger.info("Started Creating clone from template '%s'..." %template)
			
			if wait == True:
				task = template_obj.Clone(folder=destfolder, name=vm_name, spec=clonespec)
				result = wait_for_task(task)
				if result == "error":
						logger.error("Cannot Deployed VM from template: " + task.info.error.msg)
						return "FAIL"
				else:
						logger.info("Successfully Deployed VM from " + '"' + template + '"')
						return "PASS"
			else:
				task = template_obj.Clone(folder=destfolder, name=vm_name, spec=clonespec)                    
				if task.info.state  == "error":
						logger.error("Cannot Deployed VM from template: " + task.info.error.msg)
						return "FAIL"
				else:
						logger.info("Successfully Deployed VM from " + '"' + template + '"')
						return "PASS"                
		else:
				logger.error("Template not found")
				return "FAIL"

#========================================================================================================
def clone_vm(guest_name,clone_name,pwron=True,wait=True,resource_pool='Resources'):
	def find_resource_pool(name):
		rps = host_con.get_resource_pools()
		for mor, path in rps.iteritems():
			logger.info('Parsing RP %s' % path)
			if re.match('.*%s' % name,path):
				return mor
		return None
	
	# Verify the template exists
	logger.info('Finding vm %s' % guest_name)
	vm_name = find_vm(guest_name)
	if vm_name is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('vm %s found' % guest_name)
	
	# Verify the target Resource Pool exists
	logger.info('Finding resource pool %s' % resource_pool)
	resource_pool_mor = find_resource_pool(resource_pool)
	if resource_pool_mor is None:
		logger.error('ERROR: %s not found' % resource_pool)		
		
	logger.info('Resource pool %s found' % resource_pool)
 
	# Creating clone from a VM
	logger.info('Trying to clone %s to VM %s' % (guest_name,clone_name))
	
	if wait == True:
		task = vm_name.clone(clone_name, sync_run=False, power_on=pwron)
		task.wait_for_state(['success', 'error'])
		if task.get_state() == 'error':
			logger.error("Cannot create a clone from VM: " + task.get_error_message())
			return "FAIL"
		else:
			logger.info("Successfully created clone from " + '"' + guest_name + '"')
			return "PASS"
	else:
		task = vm_name.clone(clone_name, sync_run=False, power_on=pwron)
		if task.get_state() == 'error':
			logger.error("Cannot create a clone from VM: " + task.get_error_message())
			return "FAIL"
		else:
			logger.info("Successfully created clone from " + '"' + guest_name + '"')
			return "PASS"        

#========================================================================================================================			
def create_vmware_snapshot(guest_name,dc,snap_name,mem=True,quice=False):
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)

	logger.info('Virtual Machine %s found' % guest_name)		
	
	# Taking snapshot of a VM
	logger.info('Trying to take snapshot of %s' % (guest_name))
	logger.debug('%s vm state is ' %guest_name + src_vm.get_status())	
	task = src_vm.create_snapshot(snap_name, description="My_"+snap_name, sync_run=False, memory=mem, quiesce=quice)
	task.wait_for_state(['success', 'error'])
	if task.get_state() == 'error':
		logger.error("Cannot Take snapshot of a VM: " + task.get_error_message())
		return "FAIL"
	else:
		logger.info("Successfully Took snapshot of a VM " + '"' + guest_name + '"')
		return "PASS"

#=====================================================================================================================		
def revert_vmware_snapshot(guest_name,dc,snap_name):
	# Verify the VM exists
	logger.info('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('Virtual Machine %s found' % guest_name)
	
	# reverting snapshot of a VM
	logger.info('Trying to revert to snapshot %s' % (snap_name))
	vm1 = host_con.get_vm_by_name(guest_name, dc)
	logger.debug('%s vm state is ' %guest_name + vm1.get_status())
	task = vm1.revert_to_named_snapshot(snap_name, sync_run=False)
	task.wait_for_state(['success', 'error'])
	if task.get_state() == 'error':
		logger.error("Cannot revert snapshot of a VM: " + task.get_error_message())
		return "FAIL" 		
	else:
		logger.info("Successfully reverted to snapshot " + '"' + snap_name + '"')
		return "PASS" 	

#============================================================================================================================	
def delete_snap(guest_name,snap_name,delall=True):
	# Verify the VM exists
	logger.info('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('Virtual Machine %s found' % guest_name)
	if delall == True:
		# Deleting All the existing snapshots on the VM
		vm1 = host_con.get_vm_by_name(guest_name)
		logger.info("Deleting all the snaps on VM: "+guest_name)
		del_snap = vm1.delete_named_snapshot(snap_name, remove_children=True)		
		del_snap.wait_for_state(['success', 'error'])
		if del_snap.get_state() == 'error':
			logger.error("Cannot delete all the snapshots on this VM: ", task.get_error_message())
			return "FAIL" 			
		else:
			logger.info("%s and its child snaps deleted successfully" %(snap_name))
			return "PASS" 			
	else:
		# Deleting specific snapshot on the VM
		vm1 = host_con.get_vm_by_name(guest_name)
		logger.info("Deleting snapshot '%s' on VM: " %snap_name + guest_name)
		del_snap = vm1.delete_named_snapshot(snap_name, remove_children=False)		
		del_snap.wait_for_state(['success', 'error'])
		if del_snap.get_state() == 'error':
			logger.error("Cannot delete snapshot on this VM: ", task.get_error_message())
			return "FAIL" 			
		else:
			logger.info("%s snapshot deleted successfully" %(snap_name))
			return "PASS" 	

#================================================================================================================================
def create_maxta_snapshot(guest_name,snap_name,mgmtip_port,mgmt_user,mgmt_pwd,intrface='eth1'):
	# Verify the VM exists
	logger.info('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('Virtual Machine %s found' % guest_name)
	# Get maxta private ip address
	def get_ip(intrface):       
			cmd = "cat /etc/sysconfig/network-scripts/ifcfg-%s | grep -iE \"IPADDR\" | cut -c 8-" %intrface
			ip = remote_ssh_cmd(cmd,mgmtip_port,mgmt_user,mgmt_pwd)[0][0]
			logger.info("maxta IP found: "+ str(ip))
			return ip
	# Create maxta snapshot
	def create_snapshot(snapshot_cmd):
			cmd = remote_ssh_cmd(snapshot_cmd,mgmtip_port,mgmt_user,mgmt_pwd)
			rc = cmd[1]
			logger.debug("return code for create snapshot operation: "+str(rc))
			if rc == 0:                      
					return 0
			else:                   
					return 1
		
	mxip = get_ip(intrface)
	snapshot_cmd = "mxTool -z %s:2181 -c createsnapshot %s:.snapshots/%s/%s" %(mxip, guest_name, guest_name, snap_name)
	temp = create_snapshot(snapshot_cmd)
	if temp == 0:
		logger.info("\n\n=====================snapshot %s created successfully!!=======================\n"%(snap_name))
		return "PASS"
		time.sleep(30)		
	else:
		logger.info("\n\n=======================snapshot %s creation failed.==========================\n" %(snap_name))
		return "FAIL"

#==================================================================================================================================
def create_maxta_clone(snap_name,clone_name,mgmtip_port,mgmt_user,mgmt_pwd,dc,host,datastore,intrface='eth1'):
		snap_dlist = "ls -lRai /maxta/.snapshots | grep -iE '/maxta' | grep -v .vSphere* | grep -v \$policy | sed '1 d' | sed 's/://g'"
		dlist = "ls -lRai /maxta/ | grep -iE '/maxta' | grep -v .vSphere* | grep -v .snapshots | sed '1 d' | sed 's/://g'"
		flist = "ls -li %s | grep -iE .vmx | awk '{print $10}'"
		vmdir = []
		
		# Get maxta private ip
		def get_ip(intrface):
				cmd = "cat /etc/sysconfig/network-scripts/ifcfg-%s | grep -iE \"IPADDR\" | cut -c 8-" %intrface
				ip = remote_ssh_cmd(cmd,mgmtip_port,mgmt_user,mgmt_pwd)[0][0]
				logger.info("maxta private ip found: "+str(ip))
				return ip
			
		# Created maxta clone
		def create_clone(clone_cmd):
				cmd = remote_ssh_cmd(clone_cmd,mgmtip_port,mgmt_user,mgmt_pwd)
				rc = cmd[1]
				logger.debug("return code for create clone operation: "+str(rc))
				if rc == 0:                      
						return 0
				else:                   
						return 1
					
		# List directories in /maxta
		def dirlist(cmd):
				dlist = []
				list = remote_ssh_cmd(cmd,mgmtip_port,mgmt_user,mgmt_pwd)[0]                
				dlist.append(list)                
				return dlist[0]
			
		# List files in a directory
		def filelist(dir):
				cmd = flist %dir        
				list = remote_ssh_cmd(cmd,mgmtip_port,mgmt_user,mgmt_pwd)[0]
				return list
			
		# Find the vm path        
		def vm_path(cmd):
				path = dirlist(cmd)
				for i in path:
						if re.match('.*%s.*' %snap_name, i):
								j = i.split('/')                                                                
								return j[3]+"/"+snap_name
							
		# Find vmware path string
		def reg_vm_path(datastore, clone_name):
				Dstore = "[%s]" %datastore
				dir = dirlist(dlist)
				for vm in dir:
					  if re.match('.*%s.*' %clone_name, vm):
							  vmdir.append(vm)
							  j = vm.split('/')
							  vmname = j[2]                
				vmx_file = filelist(vmdir[0])          
				return Dstore+" "+vmname+"/"+vmx_file[0]
		
		# Main script                
		mxip = get_ip(intrface)      
		s_name = vm_path(snap_dlist)
		clone_cmd = "mxTool -z %s:2181 -c createclone .snapshots/%s:%s" %(mxip, s_name, clone_name)
		temp = create_clone(clone_cmd)        
		if temp == 0:                        
				logger.info("\n\n====================Clone %s created successfully!!===========================\n"%clone_name)
				time.sleep(30)
				path = reg_vm_path(datastore, clone_name)
				logger.info("\n\n================Registering %s to vsphere inventory==========================\n" %clone_name)
				register_vm(path, clone_name, dc, host, sync_run=True)
				logger.info("Powering on %s" %clone_name)
				powerOnGuest(clone_name,sync_run=False)
				return "PASS"
		else:
				logger.info("\n\n========================Clone %s creation failed.============================\n" %clone_name)
				return "FAIL"

#===============================================================================================================================
def migrate_vm(guest_name,esx_host,wait):
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)    
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('Virtual Machine %s found' % guest_name)
	
	# Get Host id       
	host_name = host_con.get_hosts()
	host_id = ""
	for key in host_name:
		value = host_name[key]
		if(value == esx_host):
			host_info = key + " : " + value
			logger.info(host_info)
			host_id += key
			logger.debug(host_id)
			break
	#Starting VM Migration
	if wait == True:
		task = src_vm.migrate(host=host_id, sync_run=False)
		task.wait_for_state(['success', 'error'])
		if task.get_state() == 'error':
			logger.error("Cannot migrate VM: " + task.get_error_message())
			return "FAIL" 		
		else:
			logger.info('Successfully migrated ' + '"' +guest_name+ '"' + ' to ' + '"' + esx_host + '"')
			return "PASS" 	    	
	else:
		task = src_vm.migrate(host=host_id, sync_run=False)
		if task.get_state() == 'error':
			logger.error("Cannot migrate VM: " + task.get_error_message())
			return "FAIL" 		
		else:
			logger.info('Successfully migrated ' + '"' +guest_name+ '"' + ' to ' + '"' + esx_host + '"')
			return "PASS"     

#======================================================================================================================================
def relocate_vm(guest_name,target_DS,esx_host=None,wait=True):
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)    
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('Virtual Machine %s found' % guest_name)
	
	# Get Host id       
	if esx_host == None:
		host_id = None
	else:
		host_name = host_con.get_hosts()
		host_id = ""
		for key in host_name:
			value = host_name[key]
			if(value == esx_host):
				host_info = key + " : " + value
				logger.info(host_info)
				host_id += key
				logger.debug(host_id)
				break
			
	# Get Datastore id
	DS = [k for k, v in host_con.get_datastores().items()
			 if v == target_DS][0]
	logger.info("Target datastore: " + DS)
	
	#Starting VM Migration
	if wait == True:
		task = src_vm.relocate(host=host_id,datastore=DS,sync_run=False)
		task.wait_for_state(['success', 'error'])
		if task.get_state() == 'error':
			logger.error("Cannot migrate VM: " + task.get_error_message())
			return "FAIL" 		
		else:
			logger.info('Successfully migrated ' + '"' +guest_name+ '"' + ' to ' + '"' + target_DS + '"')
			return "PASS" 	    	
	else:
		task = src_vm.relocate(host=host_id,datastore=DS,sync_run=False)
		if task.get_state() == 'error':
			logger.error("Cannot migrate VM: " + task.get_error_message())
			return "FAIL" 		
		else:
			logger.info('Successfully migrated ' + '"' +guest_name+ '"' + ' to ' + '"' + target_DS + '"')
			return "PASS"

#========================================================================================================================================
def delete_vm(guest_name,rmfile=True):
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		
	logger.info('Virtual Machine %s found' % guest_name)
	# Verify the VM Power on state
	status = src_vm.is_powered_on()    
	if status == True:
		#powering off VM
		powerOffGuest(guest_name)
		logger.info("%s Powered Off" %guest_name)
		time.sleep(10)
	# Starting VM deletion
	logger.info("Deleting the VM: "+guest_name)
	task = delete_vm_by_name(guest_name, remove_files=rmfile)   
	if task == 'error':
		logger.error("Cannot delete this VM: ", task.get_error_message())
		return "FAIL"            
	else:
		logger.info("%s Deleted Successfully" %(guest_name))
		return "PASS"  

#==========================================================================================================
def register_vm(path, name, datacenter, host, sync_run=True, asTemplate=False):
		try:
			dc_list = []
			if datacenter and VIMor.is_mor(datacenter):
				dc_list.append(datacenter)
			else:
				dc = host_con.get_datacenters()
				if datacenter:
					dc_list = [k for k,v in dc.iteritems() if v==datacenter]
				else:
					dc_list = list(dc.iterkeys())                   
			mor_datacenter = dc_list[0]            
			dc_props=VIProperty(host_con, mor_datacenter)            
			vmf_mor = dc_props.vmFolder._obj            
			
			vmf_props = host_con._retrieve_properties_traversal(property_names=['name'],
																obj_type='VirtualMachine')                     
			hf_mor=dc_props.hostFolder._obj
		
			#get computer resources MORs
			cr_mors=host_con._retrieve_properties_traversal(property_names=['name','host'],from_node=hf_mor,obj_type='ComputeResource')
				
			#get host MOR
			try:
				host_mor=[k for k,v in host_con.get_hosts().items() if v==host][0]                
			except IndexError, e:                
				logger.error("Cannot find host: "+host)
				
			#get computer resource MOR for host
			cr_mor=None
			for cr in cr_mors:
				if cr_mor:
					break
				for p in cr.PropSet:
					if p.Name=="host":
						for h in p.Val.get_element_ManagedObjectReference():
							if h==host_mor:
								cr_mor=cr.Obj
								break
						if cr_mor:
							break
			cr_props=VIProperty(host_con,cr_mor)           
			
			#get resource pool MOR
			rp_mor=cr_props.resourcePool._obj            
			
			# Invoke RegisterVM_Task
			request = VI.RegisterVM_TaskRequestMsg()
			_this = request.new__this(vmf_mor)
			_this.set_attribute_type(vmf_mor.get_attribute_type())
			request.set_element__this(_this)           
			request.set_element_name(name)
			request.set_element_path(path)
			pool = request.new_pool(rp_mor)
			pool.set_attribute_type(rp_mor.get_attribute_type())
			request.set_element_pool(pool)
			if host:
				if not VIMor.is_mor(host_mor):
					host = VIMor(host_mor, MORTypes.HostSystem)
				hs = request.new_host(host_mor)
				hs.set_attribute_type(host_mor.get_attribute_type())
				request.set_element_host(hs)                
			request.set_element_asTemplate(asTemplate)            
			task = host_con._proxy.RegisterVM_Task(request)._returnval
			logger.info("Starting Register VM to inventory task")
			vi_task = VITask(task, host_con)
			if sync_run:
				status = vi_task.wait_for_state([vi_task.STATE_SUCCESS,
												 vi_task.STATE_ERROR])
				if status == vi_task.STATE_ERROR:
					logger.error("Register VM operation failed, check the error message below")
					raise VIException(vi_task.get_error_message(), FaultTypes.TASK_ERROR)
				return VIVirtualMachine(host_con, vi_task.get_result()._obj)
			logger.info("Register VM to inventory task completed successfully")  
			return vi_task

		except (VI.ZSI.FaultException), e:
			raise VIApiException(e)

#==================================================================================================         
def delete_vm_by_path(path, remove_files=True):
	"""
	Unregisters a VM and remove it files from the datastore by path.
	@path is the path to VM.
	@remove_files - if True (default) will delete VM files from datastore.
	"""
	#TODO: there is an issue with wait_for_state for UnregisterV

	if not host_con:
		raise VIException("just call 'connect' before invoking this method",
						FaultTypes.NOT_CONNECTED)
	try:
		#Get VM
		vm = host_con.get_vm_by_path(path)

		if remove_files:
			#Invoke Destroy_Task
			request = VI.Destroy_TaskRequestMsg()

			_this = request.new__this(vm._mor)
			_this.set_attribute_type(vm._mor.get_attribute_type())
			request.set_element__this(_this)
			ret = host_con._proxy.Destroy_Task(request)._returnval
			task = VITask(ret, host_con)
			
			#Wait for the task to finish
			logger.info("Starting Delete VM operation")
			status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])          
			if status == task.STATE_ERROR:
				raise VIException("Error removing vm", task.get_error_message())
			logger.info("Delete VM operation completed...")
			return
		elif not remove_files:
			#Invoke UnregisterVRequestsg 
			request = VI.UnregisterVMRequestMsg()           
			logger.info("Starting Unregister VM operation")
			_this = request.new__this(vm._mor)
			_this.set_attribute_type(vm._mor.get_attribute_type())
			request.set_element__this(_this)
			ret = host_con._proxy.UnregisterVM(request)
			task = VITask(ret, host_con)
			logger.info("Unregister VM operation completed...")
			
	except (VI.ZSI.FaultException), e:
		raise VIApiException(e)

def delete_vm_by_name(name, remove_files=True):
	"""
	Unregisters a VM and remove it files from the datastore by name.
	@name is the VM name.
	@remove_files - if True (default) will delete VM files from datastore.
	"""
	#TODO: there is an issue with wait_for_state for UnregisterVM

	if not host_con:
		raise VIException("just call 'connect' before invoking this method",
						FaultTypes.NOT_CONNECTED)
	try:
		#Get VM
		vm = host_con.get_vm_by_name(name)

		if remove_files:
			#Invoke Destroy_Task
			request = VI.Destroy_TaskRequestMsg()

			_this = request.new__this(vm._mor)
			_this.set_attribute_type(vm._mor.get_attribute_type())
			request.set_element__this(_this)
			ret = host_con._proxy.Destroy_Task(request)._returnval
			task = VITask(ret, host_con)
			
			#Wait for the task to finish
			logger.info("Starting Delete VM operation")
			status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])          
			if status == task.STATE_ERROR:
				raise VIException("Error removing vm:", task.get_error_message())
			logger.info("Delete VM operation completed...")
			return
		elif not remove_files:
			#Invoke UnregisterVMRequestMsg 
			request = VI.UnregisterVMRequestMsg()
			logger.info("Starting Unregister VM operation")
			_this = request.new__this(vm._mor)
			_this.set_attribute_type(vm._mor.get_attribute_type())
			request.set_element__this(_this)
			ret = host_con._proxy.UnregisterVM(request)
			task = VITask(ret, host_con)
			logger.info("Unregister VM operation completed...")
			
	except (VI.ZSI.FaultException), e:
		raise VIApiException(e)

#==============================================================================================================
# GUEST OPERATION #
###################

def guest_list_files(guest_name,path,user,password):
	# Login to guest VM
	logger.info("Loging-in in to %s" %guest_name)
	src_vm = find_vm(guest_name)
	src_vm.login_in_guest(user, password)
	# List files in the guest VM directory path
	file_list = []
	logger.info("Listing all the files in guest VM directory")    
	list = src_vm.list_files(path)    
	for mypath in list:        
		for key,value in mypath.items():
				if key == 'path':
					file_list.append(value)                  
	return file_list
	

def guest_send_file(guest_name,user,password,local_path,guest_path,overwrite=False):
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		logger.info("reboot: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm
	logger.info('Virtual Machine %s found' % guest_name)
	# Login to guest VM
	logger.info("Loging-in in to %s" %guest_name)
	src_vm.login_in_guest(user, password)
	# Send files to the guest VM
	logger.info("Copying '%s' to guest VM path '%s'" %(local_path, guest_path))    
	task = src_vm.send_file(local_path, guest_path, overwrite=True)
	if task == 'error':
		logger.error("Cannot copy file to guest_vm: ", task.get_error_message())
		return "FAIL"             
	else:
		logger.info("Successfully copied file to guest_vm...")
		return "PASS"     

def guest_get_file(guest_name,user,password,local_path,guest_path,overwrite=False):
	# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error('ERROR: %s not found' % guest_name)		
		logger.info("reboot: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm
	logger.info('Virtual Machine %s found' % guest_name)
	# Login to guest VM
	logger.info("Loging-in in to %s" %guest_name)
	src_vm.login_in_guest(user, password)
	# Send files to the guest VM
	logger.info("Copying '%s' to guest VM path '%s'" %(local_path, guest_path))    
	task = src_vm.get_file(guest_path, local_path, overwrite=False)
	if task == 'error':
		logger.error("Cannot get file from guest_vm: ", task.get_error_message())
		return "FAIL"             
	else:
		logger.info("Successfully downloaded file from guest_vm...")
		return "PASS"     

def list_guest_process(guest_name,user,password,search_str=None):
		# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("reboot: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm
	logger.info('Virtual Machine %s found' % guest_name)
	# Login to guest VM
	logger.info("Loging-in in to %s" %guest_name)
	src_vm.login_in_guest(user, password)
	# Listing the running process
	plist = {}
	if search_str == None:
			logger.info("Listing all the running processes in %s" %guest_name)
			pprint(src_vm.list_processes())
	else:
			logger.info("Seraching for the proccess id for %s" %search_str)
			pdict = src_vm.list_processes()
			#print pdict
			for i in pdict:
					 plist[str(i['pid'])] = i['cmd_line']
			for key, value in plist.iteritems():
					if value == search_str:                                
							return int(key)        
					  

def kill_process(guest_name,user,password,pid):
		# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)		
		logger.info("reboot: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm
	logger.info('Virtual Machine %s found' % guest_name)
	# Login to guest VM
	logger.info("Loging-in in to %s" %guest_name)
	src_vm.login_in_guest(user, password)
	# killing process on a guest VM
	logger.info("Killing process with pid %s on %s" %(pid,guest_name))
	task = src_vm.terminate_process(pid)
	if task == 'error':
		logger.error("Cannot kill the process: ", task.get_error_message())
		return "FAIL"             
	else:
		logger.info("Successfully killed the process...")
		return "PASS"      
		
def start_Process(guest_name,user,password,program_path,args=None,env=None,cwd=None):
		# Verify the VM exists
	logger.info ('Finding VM %s' % guest_name)
	src_vm = find_vm(guest_name)
	if src_vm is None:
		logger.error ('ERROR: %s not found' % guest_name)			
		logger.info("reboot: Reconnecting to VIServer...")
		host_con = connectToHost(vc_ip,vc_user,vc_pwd)
		vm = host_con.get_vm_by_name(guest_name)
		src_vm = vm
	logger.info('Virtual Machine %s found' % guest_name)
	# Login to guest VM
	logger.info("Loging-in in to %s" %guest_name)
	src_vm.login_in_guest(user, password)
	# Starting process on guest VM
	logger.info("Starting process on %s" %guest_name)
	task = src_vm.start_process(program_path,args=args,env=env,cwd=cwd)
	if task == 'error':
		logger.error("Cannot start the process: ", task.get_error_message())
		return "FAIL"             
	else:
		logger.info("Successfully started the process...")
		return "PASS"   
		
#====================================================================================================================================
# IPMI TOOL #
#############

def ipmi_cmd(host,user,password,cmd):	
	logger.info("Executing IPMI command over LAN\n")
	logger.info("ipmitool -I lanplus -H " +host+ " -U " +user+ " -P " +password+ " " +cmd)
	task = os.system("ipmitool -I lanplus -H " +host+ " -U " +user+ " -P " +password+ " " +cmd)
	rc = task
	if rc == 1:
		ping_test = ping(host)
		if ping_test != 0:
			logger.error(host+" is not reachable")      
 		else:
 			logger.info(host+" is reachable\n")
			logger.error("Please provide the valid ipaddress of the BMC controller\n")
			
			
#=====================================================================================================================================
def send_mail(username,password,my_recipients,subject,message,attachments=None):
	import smtplib
	from email import encoders
	from email.mime.base import MIMEBase
	from email.mime.multipart import MIMEMultipart
	from email.mime.text import MIMEText
	import mimetypes

	COMMASPACE = ', '
	sender = username
	gmail_password = password
	recipients = my_recipients
	
	# Create the enclosing (outer) message
	outer = MIMEMultipart()
	outer['Subject'] = subject
	outer['To'] = COMMASPACE.join(recipients)
	outer['From'] = sender
	outer.attach(MIMEText(message))
	outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'

	# List of attachments
	attachments = attachments

	# Add the attachments to the message
	if attachments != None:
		for file in attachments:
			try:
				with open(file, 'rb') as fp:
					msg = MIMEBase('application', "octet-stream")
					msg.set_payload(fp.read())
				encoders.encode_base64(msg)
				msg.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file))
				outer.attach(msg)
			except:
				logger.error("Unable to open one of the attachments. Error: ", sys.exc_info()[0])
				raise

	composed = outer.as_string()

	# Send the email
	try:
		smtp_host = 'smtp.gmail.com'
		smtp_port = 587
		server = smtplib.SMTP()
		server.connect(smtp_host,smtp_port)
		server.ehlo()
		server.starttls()
		#server.login(user,base64.b64decode(passw))	
		server.login(sender, gmail_password)
		server.sendmail(sender, recipients, composed)
		server.quit()
		logger.info("Email sent successfully!")
	except:
		logger.error("Unable to send the email. Error: ", sys.exc_info()[0])
		raise

#===========================================================================================================================================================
### This section of code is experimental and may not work on platform other than windows. vSphere-PowerCLI tools must be install first in order to execute this section.
def powercli_script(script):
	check_pf = check_platform()
	if check_pf == "\\":
		powershell = r'%SystemRoot%\\system32\\windowspowershell\\v1.0\\powershell.exe'	
		os.chdir("C:\\Program Files (x86)\\VMware\\Infrastructure\\vSphere PowerCLI")	
		logger.info("Trying to execute power CLI script")
		os.system(powershell + " -PSConsoleFile " + "./vim.psc1 " + "-command " + '"&{' + script +'}"')
	else:
		logger.error("Sorry!!, We don't support executing powershell scripts on linux distribution...")

def call_pwrCLI(script):
	logger.info("Executing power cli script to create clone from template...")
	powercli_script(script)
	logger.info("Successfully Submitted power CLI script execution request...")
