#!/usr/bin/python
#
# Copyright 2010, Pall Sigurdsson <palli@opensource.is>
#
# This script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# About this script
# 
# This script will check the status of a remote Lenovo Enterprise Flex Chassis
# orginal file check_ibm_bladecenter.py renamed and modified by Silvio Erdenberger, 
#
# version 1.3
# 8.12.2017
# adding
# * add coolingzone feature 
#
# fixes
# * fix wrong compares in fans (fans)
#
# changes
# * rewrite the check_fans
#
#
# version 1.2
# 30.11.2017
# changes 
# * renamed --snmp-password to --snmp_apassword
# * fix a wrong validation of Authentication password in the options parameter
# * fix some typo in the help
# 
# version 1.1
# 17.11.2017
# change filename to check_lenovo_flex.py
# there are several changes to the IBM Bladecenter, whic are not compatible
# changes in version 1.1
# * add possibility to a Privacy Password for authPriv in snmp_security_level
# * required parameter depending on --snmp_security_level
# * add authentication encryption and password
# * add privacy encryption and password
#
# powermodules
#
# system-health -> adjust to flex chassis
#  if no error, the error oid don't exist
#
# temperature -> no change
#
# chassis-status to flex adjusted 
#
# bladehealth
#
# fans -> adjust to flex chassis
#
# coolingzones 
# implemented on fan based devices
# TODO change the OID ChassisCoolingZone
# but some issues appear
#  
# switchmodules
#  


# No real need to change anything below here
version="1.3"
ok=0
warning=1
critical=2
unknown=3 
not_present = -1 
exit_status = -1

state = {}
state[not_present] = "Not Present"
state[ok] = "OK"
state[warning] = "Warning"
state[critical] = "Critical"
state[unknown] = "Unknown"

longserviceoutput="\n"
perfdata=""
summary=""
sudo=False

from sys import exit
from sys import argv
from os import getenv,putenv,environ
import subprocess


# Parse some Arguments
from optparse import OptionParser
parser = OptionParser()
parser.add_option("-m","--mode", dest="mode",
	help="Which check mode is in use (powermodules,system-health,temperature,fans,memories,disks,chassis-status,bladehealth,,switchmodules,coolingzones)")
parser.add_option("-H","--host", dest="host",
	help="Hostname or IP address of the host to check")
parser.add_option("-w","--warning", dest="warning_threshold",
	help="Warning threshold", type="int", default=None)
parser.add_option("-c","--critical", type="int", dest="critical_threshold",
	help="Critical threshold", default=None)
parser.add_option("-e","--exclude", dest="exclude",
	help="Exclude specific object", default=None)
parser.add_option("-v","--snmp_version", dest="snmp_version",
	help="SNMP Version to use (1, 2c or 3)", default="1")
parser.add_option("-u","--snmp_username", dest="snmp_username",
	help="SNMP username (only with SNMP v3)", default=None)
parser.add_option("-C","--snmp_community", dest="snmp_community",
	help="SNMP Community (only with SNMP v1|v2c)", default=None)
parser.add_option("-p","--snmp_apassword", dest="snmp_apassword",
	help="SNMP authentication password (only with SNMP v3)", default=None)
parser.add_option("-a","--snmp_aprotocol", dest="snmp_aprotocol",
	help="SNMP authentication protocol (SHA only with SNMP v3)", default=None)
parser.add_option("-x","--snmp_ppassword", dest="snmp_ppassword",
	help="SNMP privacy password (only with SNMP v3)", default=None)
parser.add_option("-X","--snmp_pprotocol", dest="snmp_pprotocol",
	help="SNMP privacy protocol AES||DES (only with SNMP v3)", default=None)
parser.add_option("-l","--snmp_security_level", dest="snmp_seclevel",
	help="SNMP security level (only with SNMP v3) (noAuthNoPriv|authNoPriv|authPriv)", default=None)
parser.add_option("-t","--snmp_timeout", dest="snmp_timeout",
	help="Timeout in seconds for SNMP", default=10)
parser.add_option("-d","--debug", dest="debug",
	help="Enable debugging (for troubleshooting", action="store_true", default=False)

(opts,args) = parser.parse_args()


if opts.host == None:
	parser.error("Hostname (-H) is required.")
if opts.mode == None:
	parser.error("Mode (--mode) is required.")

snmp_options = ""
def set_snmp_options():
	global snmp_options
	if opts.snmp_version is not None:
		snmp_options = snmp_options + " -v%s" % opts.snmp_version
	if opts.snmp_version == "3":
		if opts.snmp_username is None:
			parser.error("--snmp_username required with --snmp_version=3")
		if opts.snmp_seclevel is None:
			parser.error("--snmp_security_level required with --snmp_version=3")
		if opts.snmp_seclevel == "noAuthNoPriv":
			snmp_options = snmp_options + " -l %s -u %s " % (opts.snmp_seclevel,opts.snmp_username)
		if opts.snmp_seclevel == "authNoPriv":
			if opts.snmp_apassword is None:
				parser.error("--snmp_apassword required with --snmp_version=3")
			if opts.snmp_aprotocol is None:
				parser.error("--snmp_aprotocol required with --snmp_version=3")
			snmp_options = snmp_options + " -l %s -u %s -a %s -A %s " % (opts.snmp_seclevel,opts.snmp_username,opts.snmp_aprotocol,opts.snmp_apassword)
		if opts.snmp_seclevel == "authPriv":
			if opts.snmp_pprotocol is None:
				parser.error("--snmp_pprotocol required with --snmp_version=3")
			if opts.snmp_ppassword is None:
				parser.error("--snmp_ppassword required with --snmp_version=3")
			if opts.snmp_apassword is None:
				parser.error("--snmp_apassword required with --snmp_version=3")
			if opts.snmp_aprotocol is None:
				parser.error("--snmp_aprotocol required with --snmp_version=3")
			snmp_options = snmp_options + " -l %s -u %s -a %s -A %s -x %s -X %s " % (opts.snmp_seclevel,opts.snmp_username,opts.snmp_aprotocol,opts.snmp_apassword,opts.snmp_pprotocol,opts.snmp_ppassword)
	else:
		if opts.snmp_community is None:
			parser.error("--snmp_community is required with --snmp_version=1|2c")
		snmp_options = snmp_options + " -c %s " % opts.snmp_community 
	snmp_options += " -t %s " % (opts.snmp_timeout)

def error(errortext):
        print "* Error: %s" % errortext
        exit(unknown)

def debug( debugtext ):
        if opts.debug:
                print  debugtext

def nagios_status( newStatus ):
	global exit_status
	exit_status = max(exit_status, newStatus)
	return exit_status

'''runCommand: Runs command from the shell prompt. Exit Nagios style if unsuccessful'''
def runCommand(command):
  debug( "Executing: %s" % command )
  proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE,)
  stdout, stderr = proc.communicate('through stdin to stdout')
  if proc.returncode > 0:
    print "Error %s: %s\n command was: '%s'" % (proc.returncode,stderr.strip(),command)
    debug("results: %s" % (stdout.strip() ) )
    if proc.returncode == 127: # File not found, lets print path
        path=getenv("PATH")
        print "Check if your path is correct %s" % (path)
    if stderr.find('Password:') == 0 and command.find('sudo') == 0:
      print "Check if user is in the sudoers file"
    if stderr.find('sorry, you must have a tty to run sudo') == 0 and command.find('sudo') == 0:
      print "Please remove 'requiretty' from /etc/sudoers"
    exit(unknown)
  else:
    return stdout

def end():
	global summary
	global longserviceoutput
	global perfdata
	global exit_status
        print "%s - %s | %s" % (state[exit_status], summary,perfdata)
        print longserviceoutput
	if exit_status < 0: exit_status = unknown
        exit(exit_status)

def add_perfdata(text):
        global perfdata
        text = text.strip()
        perfdata = perfdata + " %s " % (text)

def add_long(text):
        global longserviceoutput
        longserviceoutput = longserviceoutput + text + '\n'

def add_summary(text):
	global summary
	summary = summary + text

def set_path(path):
	current_path = getenv('PATH')
	if current_path.find('C:\\') > -1: # We are on this platform
		if path == '':
			pass
		else: path = ';' + path
	else:	# Unix/Linux, etc
		if path == '': path = ":/usr/sbin"
		else: path = ':' + path
	current_path = "%s%s" % (current_path,path)
	environ['PATH'] = current_path



def snmpget(oid):
	snmpgetcommand = "snmpget %s %s %s" % (snmp_options,opts.host,oid)
	output = runCommand(snmpgetcommand)
	oid,result = output.strip().split(' = ', 1)
	resultType,resultValue = result.split(': ',1)
	if resultType == 'STRING': # strip quotes of the string
		resultValue = resultValue[1:-1]
	return resultValue

# snmpwalk -v3 -u v3get mgmt-rek-proxy-p02 -A proxy2011 -l authNoPriv 1.3.6.1.4.1.15497
def snmpwalk(base_oid):
	snmpwalkcommand = "snmpwalk %s %s %s" % (snmp_options, opts.host, base_oid)
	output = runCommand(snmpwalkcommand + " " + base_oid)
	return output

def getTable(base_oid):
	myTable = {}
	output = snmpwalk(base_oid)
	for line in output.split('\n'):
		tmp = line.strip().split(' = ', 1)
		if len(tmp) == 2:
			oid,result = tmp
		else:
			result = result + tmp[0]
#			continue
		tmp = result.split(': ',1)
		if len(tmp) > 1:
			resultType,resultValue = tmp[0],tmp[1]
		else:
			resultType = None
			resultValue = tmp[0]
		if resultType == 'STRING': # strip quotes of the string
			resultValue = resultValue[1:-1]
		index = oid.strip().split('.')
		column = int(index.pop())
		row = int(index.pop())
		if not myTable.has_key(column): myTable[column] = {}
		myTable[column][row] = resultValue
	return myTable

def check_powermodules():
                                 #BASE OID
				 #               #SUPPORT PROCESSOR
                                 #               #  #CMM OID
				 #               #  # #MONITORS
                                 #               #  # # #POWER MOD
	powermodules = getTable('1.3.6.1.4.1.2.3.51.3.1.11')
	index,exists,status,details = (1,2,6,4)
	num_ok = 0
	for i in powermodules.values():
		myIndex = i[index]
		myStatus = i[status]
		myDetails = i[details]
		myExists = i[exists]
		if myIndex == opts.exclude: continue
		if myStatus != "Normal":
			nagios_status(warning)
			add_summary( 'Powermodule "%s" status "%s". %s. ' % (myIndex,myStatus,myDetails) )
		else:
			num_ok = num_ok + 1
		add_long('Powersupply "%s" status "%s". %s. ' % (myIndex,myStatus,myDetails) )
	add_summary( "%s out of %s powermodules are healthy" % (num_ok, len(powermodules) ) )
	add_perfdata( "'Number of powermodules'=%s" % (len(powermodules) ) )
			
	nagios_status(ok)

def check_fans():
	" Check fan status "
                         #BASE OID
                         #           #CMM OID
                         #           #            #FAN OID
	fans = getTable("1.3.6.1.4.1.2.3.51.3.1.3.2.1")

	chassisFanIndex,chassisFanDescr,chassisFanSpeed,chassisFanHealthStatus = (1,2,3,10)

        for i in fans.values():
			debug("i %s" % i)
			debug("chassisFanSpeed %s" % chassisFanSpeed)
			if i[chassisFanHealthStatus] !="Unknown": # Unknown => notPresent
				add_long( "Fan %s state=%s speed=%s" % (i[chassisFanIndex],i[chassisFanHealthStatus],i[chassisFanSpeed]) )
				add_perfdata("Fan%s=%s" %(i[chassisFanIndex],chassisFanSpeed ))
				# Check fan i
				if i[chassisFanHealthStatus] == "Normal":
					nagios_status(ok)
				else:
					add_summary("Fan%s NOT OK. " % i[chassisFanIndex])
					nagios_status(warning)

def check_memories():
	" Check module memories status "
                         #BASE OID
                         #           #CMM OID
                         #           #            #FAN OID
	memories = getTable("1.3.6.1.4.1.2.3.51.3.1.5.21.1")

	chassisMemIndex,chassisMemDescr,chassisMemSerialNumber,chassisMemHealthStatus = (1,2,4,8)

        for i in memories.values():
			debug("i %s" % i)
			debug("chassisMemSerialNumber %s" % chassisMemSerialNumber)
			if i[chassisMemHealthStatus] !="Unknown": # Unknown => notPresent
				add_long( "Memory %s state=%s Description=%s" % (i[chassisMemIndex],i[chassisMemHealthStatus],i[chassisMemDescr]) )
				add_perfdata("Memory%s=%s" %(i[chassisMemIndex],chassisMemDescr))
				# Check module i
				if i[chassisMemHealthStatus] == "Normal":
					nagios_status(ok)
				else:
					add_summary("Mem%s NOT OK. " % i[chassisMemIndex])
					nagios_status(warning)

		


def check_systemhealth():
	systemhealthstat = snmpget('1.3.6.1.4.1.2.3.51.3.1.4.1.0')
	index,severity,description = (1,2,3)
	# Check overall health
	if systemhealthstat == '255':
		nagios_status(ok)
		add_summary("Lenovo 3650 health: OK. ")
	elif systemhealthstat == "2":
		nagios_status(warning)
		add_summary("Non-Critical Error. ")
	elif systemhealthstat == "4":
		nagios_status(critical)
		add_summary("System-Level Error. ")
	elif systemhealthstat == "0":
		nagios_status(critical)
		add_summary("Critical. ")
	else:
		nagios_status(unknown)
		add_summary("Lenovo 3050 health unkown (oid 1.3.6.1.4.1.2.3.51.3.1.4.1.0 returns %s). " % systemhealthstat)
	if systemhealthstat == "2" or systemhealthstat == "4" or systemhealthstat == "0": 
		summary = getTable('1.3.6.1.4.1.2.3.51.3.1.4.2.1')
		for row in summary.values():
			if row[severity] == 'Good':
				nagios_status(ok)
			elif row[severity] == 'Warning':
				nagios_status(warning)
			else:
				nagios_status(critical)
			text_row_description = row[description]
			text_row_description = text_row_description.replace(" ", "")
			text_row_description = text_row_description.decode("hex")
			add_summary( "%s. " % (text_row_description) )
			add_long( "* %s. " % (text_row_description) )
	
def check_temperature():

	" Check temperature status "
							#BASE OID
							#           #CMM OID
							#           #            #TEMPERATURE OID
	thermometers = getTable("1.3.6.1.4.1.2.3.51.3.1.1.2.1")

	chassisTempIndex,chassisTempDescr,chassisTempReading,chassisTempHealthStatus = (1,2,3,11)

	for i in thermometers.values():
		debug("i %s" % i)
		debug("chassisTempReading %s" % chassisTempReading)
		if i[chassisTempHealthStatus] !="Unknown": # Unknown => notPresent
			add_long( " %s TempHealthStatus=%s TempReading=%s TempDescr=%s" % (i[chassisTempIndex],i[chassisTempHealthStatus],i[chassisTempReading],i[chassisTempDescr]) )
			add_perfdata("Temp%s=%s" %(i[chassisTempIndex],chassisTempHealthStatus ))
			# Check disk i
			if i[chassisTempHealthStatus] == "Normal":
				nagios_status(ok)
			else:
				add_summary("Temp%s NOT OK. " % i[chassisTempIndex])
				nagios_status(warning)
	
def check_disks():

	" Check disks status "
							#BASE OID
							#           #CMM OID
							#           #            #DISKS OID
	disks = getTable(".1.3.6.1.4.1.2.3.51.3.1.12.2.1")

	chassisDiskIndex,chassisDiskName,chassisDiskHealthStatus = (1,2,3)

	for i in disks.values():
		debug("i %s" % i)
		debug("chassisDisksHealthStatus %s" % chassisDiskHealthStatus)
		if i[chassisDiskHealthStatus] !="Unknown": # Unknown => notPresent
			add_long( " %s DiskName=%s HealthStatus=%s" % (i[chassisDiskIndex],i[chassisDiskName],i[chassisDiskHealthStatus]) )
			add_perfdata("Temp%s=%s" %(i[chassisDiskIndex],chassisDiskHealthStatus ))
			# Check disk i
			if i[chassisDiskHealthStatus] == "Normal":
				nagios_status(ok)
			else:
				add_summary("Disk%s NOT OK. " % i[chassisDiskIndex])
				nagios_status(warning)
	

if __name__ == '__main__':
	try:
		set_snmp_options()
		if opts.mode == 'powermodules':
			check_powermodules()
		elif opts.mode == 'system-health':
			check_systemhealth()
		elif opts.mode == 'temperature':
			check_temperature()
		elif opts.mode == 'chassis-status':
			check_chassis_status()
		elif opts.mode == 'memories':
			check_memories()
		elif opts.mode=='disks':
			check_disks()
		elif opts.mode == 'bladehealth':
			check_bladehealth()
		elif opts.mode == 'fans':
			check_fans()
		elif opts.mode == 'coolingzones':
			check_coolingzones()
		elif opts.mode == 'switchmodules':
			check_switchmodules()
		else:
			parser.error("%s is not a valid option for --mode" % opts.mode)
	except Exception, e:
		print "Unhandled exception while running script: %s" % e
		exit(unknown)
	end()

