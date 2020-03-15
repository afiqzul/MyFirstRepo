#!/bin/sh
#
# $Id$ csmc_config v1.3
#
# Script will configure all auditd configuration including audisp syslog plugin
#
# Contact: nor-idzuwan.mohammad@t-systems.com
# more info on the script can be found here
# FQDN http://aa1lh111.europe.shell.com/pub/csmc/readme.txt
# From Customer Network http://145.59.200.65/pub/csmc/readme.txt
# From AdminLAN http://177.8.14.111/pub/csmc/readme.txt
#
#

if [ "$(id -u)" != "0" ]
then
        echo "Only root can perform this."
        exit 1
fi

HOSTAME=$(hostname)

imgver()
{
        if [ ! -e "/etc/imageversion" ]
        then
                echo "ERROR: Image version not found."
                exit 1
        fi
        cat "/etc/imageversion" | head -1
}

IMGVERSION=$(imgver)
NOSUPPORT=''

if [ -e "/etc/SuSE-release" ]
then
### for SuSE only
case "$IMGVERSION" in
    s11.2.3|s11.3.2-1|s11.3.4)
		T_RSYS=$(df /etc/syslog-ng |grep etc#syslog-ng |wc -l)
        RSYSLOG=0
        ;;
    s11.3.6|s11.3.9|s11.4.1|s11.4.3|s11.4.5|s11.4.6|s11.4.8|s11.4.14|s12.2.5|s12.2.7|s12.2.10|s12.3.1|s12.4.1|s12.4.3)
		T_RSYS=$(df /etc/rsyslog.d |grep etc#rsyslog.d |wc -l)
        RSYSLOG=1
        ;;
        s11.2.1|s11.2.2|s10.4.7|s10.4.5|s10.4.9)
        NOSUPPORT=yes
        ;;
   *)
      echo "Error: Unknown version ${IMGVERSION}"
      exit 1
   ;;
esac
fi

if [ -n "$NOSUPPORT" ]
        then
        echo "$IMGVERSION is not supported by CSMC solution"
        exit 1
fi

export PATH=/sbin:/bin:/usr/sbin:/usr/bin

## R7 CONFIG START ##
r7_config (){
# Prepare config

# Auditd
echo "================================="
echo " Configuring CSMC default config "
echo "================================="
echo ""
echo "preparing /etc/audit/auditd.conf"
if [ -w "/etc/audit/auditd.conf" ]
        then
        cp /etc/audit/auditd.conf /etc/audit/auditd.conf.CSMC.$(date +%d-%m-%Y)
        cat > /etc/audit/auditd.conf <<EOF
#
# This file controls the configuration of the audit daemon
#

log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
write_logs = no
priority_boost = 4
flush = NONE
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 6
max_log_file_action = ROTATE
space_left = 200
space_left_action = SUSPEND
action_mail_acct = root
admin_space_left = 75
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port =
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF
        else
        echo "ERROR: /etc/audit/auditd.conf not writable by root "
fi

# audit.rules
echo "preparing /etc/audit/rules.d/audit.rules"
if [ -w "/etc/audit/rules.d/audit.rules" ]
        then
                cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.CSMC.$(date +%d-%m-%Y)
                cat > /etc/audit/rules.d/audit.rules <<EOF
## This file contains the auditctl rules that are loaded
## whenever the audit daemon is started via the initscripts.
## The rules are simply the parameters that would be passed
## to auditctl.
##
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 16384

## Failure Mode
## Possible values are 0 (silent), 1 (printk, print a failure message),
## and 2 (panic, halt the system).
-f 1

## NOTE:
## 1) if this is being used on a 32 bit machine, comment out the b64 lines
## 2) These rules assume that login under the root account is not allowed.
## 3) It is also assumed that 500 represents the first usable user account.
## 4) If these rules generate too much spurious data for your tastes, limit the
## the syscall file rules with a directory, like -F dir=/etc
## 5) You can search for the results on the key fields in the rules
##
##
## (GEN002880: CAT II) The IAO will ensure the auditing software can
## record the following for each audit event:
##- Date and time of the event
##- Userid that initiated the event
##- Type of event
##- Success or failure of the event
##- For I&A events, the origin of the request (e.g., terminal ID)
##- For events that introduce an object into a userÃ¢ess space, and
##  for object deletion events, the name of the object, and in MLS
##  systems, the objectÃ¢rity level.
##
## Things that could affect time
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-w /etc/localtime -p wa -k time-change

## Things that affect identity
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Things that could affect system locale
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

## Things that could affect MAC policy
-w /etc/selinux/ -p wa -k MAC-policy

##- Export to media (successful)
## You have to mount media before using it. You must disable all automounting
## so that its done manually in order to get the correct user requesting the
## export
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k export

##- All system administration actions
##- All security personnel actions
##
## Look for pam_tty_audit and add it to your login entry point's pam configs.
## If that is not found, use sudo which should be patched to record its
## commands to the audit system. Do not allow unrestricted root shells or
## sudo cannot record the action.
-w /etc/sudoers -p wa -k actions
-w /etc/sudo/sudoers -p wa -k actions

## Put your own watches after this point
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /bin/passwd -p x -k identity

## Make the configuration immutable - reboot is required to change audit rules
-e 2
EOF
        else
        echo "ERROR: /etc/audit/rules.d/audit.rules not writable by root "
fi

# Audispd.conf
echo "preparing /etc/audisp/audispd.conf"
if [ -w "/etc/audisp/audispd.conf" ]
        then
        cp /etc/audisp/audispd.conf /etc/audisp/audispd.conf.CSMC.$(date +%d-%m-%Y)
        cat > /etc/audisp/audispd.conf <<EOF
#
# This file controls the configuration of the audit event
# dispatcher daemon, audispd.
#

q_depth = 80
overflow_action = IGNORE
priority_boost = 4
#max_restarts = 10
name_format = HOSTNAME
#name = mydomain
EOF
        else
        echo "ERROR: /etc/audisp/audispd.conf not writable by root "
fi

# /etc/audisp/plugins.d/syslog.conf
echo "preparing /etc/audisp/plugins.d/syslog.conf"
if [ -w "/etc/audisp/plugins.d/syslog.conf" ]
        then
        cp /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.CSMC.$(date +%d-%m-%Y)
        cat > /etc/audisp/plugins.d/syslog.conf <<EOF
# This file controls the configuration of the syslog plugin.
# It simply takes events and writes them to syslog. The
# arguments provided can be the default priority that you
# want the events written with. And optionally, you can give
# a second argument indicating the facility that you want events
# logged to. Valid options are LOG_LOCAL0 through 7.

active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO
format = string
EOF
        else
        echo "ERROR: /etc/audisp/plugins.d/syslog.conf not writable by root"
fi
if [ -e /etc/rsyslog.d/csmc.conf ]
        then
        mv /etc/rsyslog.d/csmc.conf /etc/rsyslog.d/01_csmc.conf
fi
}
## R7 CONFIG END ##

## R5/6/SLES CONFIG START ##
c_config (){
# Prepare config

# Auditd
echo "================================="
echo " Configuring CSMC default config "
echo "================================="
echo ""
echo "preparing /etc/audit/auditd.conf"
if [ -w "/etc/audit/auditd.conf" ]
        then
        cp /etc/audit/auditd.conf /etc/audit/auditd.conf.CSMC.$(date +%d-%m-%Y)
        cat > /etc/audit/auditd.conf <<EOF
#
# This file controls the configuration of the audit daemon
#

log_file = /var/log/audit/audit.log
log_format = NOLOG
log_group = root
priority_boost = 4
flush = NONE
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 6
max_log_file_action = ROTATE
space_left = 200
space_left_action = SUSPEND
action_mail_acct = root
admin_space_left = 75
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port =
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF
        else
        echo "ERROR: /etc/audit/auditd.conf not writable by root "
fi

# audit.rules
echo "preparing /etc/audit/audit.rules"
if [ -w "/etc/audit/audit.rules" ]
        then
                cp /etc/audit/audit.rules /etc/audit/audit.rules.CSMC.$(date +%d-%m-%Y)
                cat > /etc/audit/audit.rules <<EOF
## This file contains the auditctl rules that are loaded
## whenever the audit daemon is started via the initscripts.
## The rules are simply the parameters that would be passed
## to auditctl.
##
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 16384

## Failure Mode
## Possible values are 0 (silent), 1 (printk, print a failure message),
## and 2 (panic, halt the system).
-f 1

## NOTE:
## 1) if this is being used on a 32 bit machine, comment out the b64 lines
## 2) These rules assume that login under the root account is not allowed.
## 3) It is also assumed that 500 represents the first usable user account.
## 4) If these rules generate too much spurious data for your tastes, limit the
## the syscall file rules with a directory, like -F dir=/etc
## 5) You can search for the results on the key fields in the rules
##
##
## (GEN002880: CAT II) The IAO will ensure the auditing software can
## record the following for each audit event:
##- Date and time of the event
##- Userid that initiated the event
##- Type of event
##- Success or failure of the event
##- For I&A events, the origin of the request (e.g., terminal ID)
##- For events that introduce an object into a userâdress space, and
##  for object deletion events, the name of the object, and in MLS
##  systems, the objectâcurity level.
##
## Things that could affect time
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-w /etc/localtime -p wa -k time-change

## Things that affect identity
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Things that could affect system locale
-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

## Things that could affect MAC policy
-w /etc/selinux/ -p wa -k MAC-policy

##- Export to media (successful)
## You have to mount media before using it. You must disable all automounting
## so that its done manually in order to get the correct user requesting the
## export
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export

##- All system administration actions
##- All security personnel actions
##
## Look for pam_tty_audit and add it to your login entry point's pam configs.
## If that is not found, use sudo which should be patched to record its
## commands to the audit system. Do not allow unrestricted root shells or
## sudo cannot record the action.
-w /etc/sudoers -p wa -k actions
-w /etc/sudo/sudoers -p wa -k actions

## Put your own watches after this point
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /bin/passwd -p x -k identity

## Make the configuration immutable - reboot is required to change audit rules
-e 2
EOF
        else
        echo "ERROR: /etc/audit/audit.rules not writable by root "
fi

# Audispd.conf
echo "preparing /etc/audisp/audispd.conf"
if [ -w "/etc/audisp/audispd.conf" ]
        then
        cp /etc/audisp/audispd.conf /etc/audisp/audispd.conf.CSMC.$(date +%d-%m-%Y)
        cat > /etc/audisp/audispd.conf <<EOF
#
# This file controls the configuration of the audit event
# dispatcher daemon, audispd.
#

q_depth = 80
overflow_action = IGNORE
priority_boost = 4
#max_restarts = 10
name_format = HOSTNAME
#name = mydomain
EOF
        else
        echo "ERROR: /etc/audisp/audispd.conf not writable by root "
fi

# /etc/audisp/plugins.d/syslog.conf
echo "preparing /etc/audisp/plugins.d/syslog.conf"
if [ -w "/etc/audisp/plugins.d/syslog.conf" ]
        then
        cp /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.CSMC.$(date +%d-%m-%Y)
        cat > /etc/audisp/plugins.d/syslog.conf <<EOF
# This file controls the configuration of the syslog plugin.
# It simply takes events and writes them to syslog. The
# arguments provided can be the default priority that you
# want the events written with. And optionally, you can give
# a second argument indicating the facility that you want events
# logged to. Valid options are LOG_LOCAL0 through 7.

active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO
format = string
EOF
        else
        echo "ERROR: /etc/audisp/plugins.d/syslog.conf not writable by root"
fi
if [ -e /etc/rsyslog.d/csmc.conf ]
        then
        mv /etc/rsyslog.d/csmc.conf /etc/rsyslog.d/01_csmc.conf
fi
}

## CONFIG END ##

## RHEL CHECK START ##
rhel_cfg () {
if [[ "$IMGVERSION" != r5.8* ]]
        then
		echo ""
		# call config function
		if [[ "$IMGVERSION" != r7* ]]
		then
			c_config
		else
			r7_config
		fi
		echo "Preparing /etc/rsyslog.d/01_csmc.conf, please edit this files manually for activation"
		cat > /etc/rsyslog.d/01_csmc.conf <<EOF
# Send a copy to CSMC Syslog Daemon
#auth,user,authpriv.=info @<HOST>:514
EOF
		echo ""
		echo "==========="
		echo " IMPORTANT "
		echo "==========="
		echo ""
        echo "Please make sure OS init script is installed: curl -s http://145.59.200.65/pub/Shellify/install_init.sh | /bin/bash "
        echo ""
        else
		echo ""
		echo "Not rsyslog manual syslog.conf configuration required Please check runbook"
		exit 0
fi
} # END RHEL CHECK

## SLES CHECK START ##
sles_cfg () {
if [[ "$RSYSLOG" != 0 ]]
        then
		echo ""
		# call config function
		c_config
        echo "Preparing /etc/rsyslog.d/01_csmc.conf, please edit this files manually for activation"
        cat > /etc/rsyslog.d/01_csmc.conf <<EOF
# Send a copy to CSMC Syslog Daemon
#auth,user,authpriv.=info @<HOST>:514
EOF
		echo ""
		echo "==========="
		echo " IMPORTANT "
		echo "==========="
		echo ""
        echo "Please make sure OS init script is installed: curl -s http://145.59.200.65/pub/Shellify/install_init.sh | /bin/bash "
        echo ""
        else
		echo ""
		# call config function
		c_config
		echo ""
        echo "Not rsyslog manual syslog-ng configuration required Please check runbook"
fi
} # END SLES CHECK

# Verify mount point
m_verify () {
local T_AUDIT=$(df /etc/audit |grep etc#audit |wc -l)
local T_AUDISP=$(df /etc/audisp |grep etc#audisp |wc -l)
local T_RSYS=$(df /etc/rsyslog.d |grep etc#rsyslog.d |wc -l)
local T_MOUNT=''
echo ""
echo "======================="
echo " Verifying mount mount "
echo "======================="
echo ""
if [ "$T_AUDIT" != "0" ]
        then
        echo "/etc/audit - OK"
        else
        echo "/etc/audit - NOT mounted"
		T_MOUNT=yes
fi
if [ "$T_AUDISP" != "0" ]
        then
        echo "/etc/audisp - OK"
        else
        echo "/etc/audisp - NOT mounted"
		T_MOUNT=yes
fi

if [[ "$IMGVERSION" == r* ]]
	then
	if [[ "$IMGVERSION" != r5.8* ]]
		then
        if [ "$C_RSYS" != "0" ]
        then
                echo "/etc/rsyslog.d mount - OK"
        else
                echo "/etc/rsyslog.d - NOT mounted"
		fi 
	fi
else
	if [[ "$RSYSLOG" != 1 ]]
        then
		local C_SYS=$(df /etc/syslog-ng |grep etc#syslog-ng |wc -l)
        # SYSLOG-NG
			if [ "$C_SYS" != "0" ]
			then
                echo "/etc/syslog-ng mount - OK"
			else
			echo "/etc/syslog-ng - NOT mounted"
			fi
    else
    # RSYSLOG.D
		if [ "$T_RSYS" != "0" ]
        then
                echo "/etc/rsyslog.d mount - OK"
        else
                echo "/etc/rsyslog.d - NOT mounted"
        fi
        # RSYSLOG.D END
	fi
fi
	
if [ -n "$T_MOUNT" ]
	then
	echo ""
	echo "ERR: Missing mount point please do manual check on the above list"
	echo ""
	exit 1
fi
}

# Mount point check
m_check() {
local REPAIR=''
echo ""
echo "======================================="
echo " Checking CSMC mount-point requirement "
echo "======================================="
echo ""
# AUDIT
local C_AUDIT=$(df /etc/audit |grep etc#audit |wc -l)
if [ "$C_AUDIT" != "0" ]
then
        echo "/etc/audit mount - OK"
        else
        echo "/etc/audit - NOT mounted"
        if [ ! -e "/cAppCom/mounts/etc#audit" ]
        then
                echo "setting up /etc/audit as seperate mount point"
                echo '*:@*-%5.%6.%7.%8' > /cAppCom/mounts/etc#audit
                REPAIR=yes
        else
        REPAIR=yes
        fi
fi
# AUDIT END

# AUDISP
local C_AUDISP=$(df /etc/audisp |grep etc#audisp |wc -l)
if [ "$C_AUDISP" != "0" ]
then
        echo "/etc/audisp mount - OK"
else
        echo "/etc/audisp - NOT mounted"
        if [ ! -e "/cAppCom/mounts/etc#audisp" ]
        then
                echo "setting up /etc/audit as seperate mount point"
                echo '*:@*-%5.%6.%7.%8' > /cAppCom/mounts/etc#audisp
                REPAIR=yes
        else
        REPAIR=yes
        fi
fi
# AUDISP END

# RSYSLOG.D
# RHEL
if [[ "$IMGVERSION" == r* ]]
	then
	if [[ "$IMGVERSION" != r5.8* ]]
		then
        local C_RSYS=$(df /etc/rsyslog.d |grep etc#rsyslog.d |wc -l)
        if [ "$C_RSYS" != "0" ]
        then
                echo "/etc/rsyslog.d mount - OK"
        else
                echo "/etc/rsyslog.d - NOT mounted"
                if [ ! -e "/cAppCom/mounts/etc#rsyslog.d" ]
                then
                        echo "setting up /etc/rsyslog.d as seperate mount point"
                        echo '*:@*-%5.%6.%7.%8' > /cAppCom/mounts/etc#rsyslog.d
                        REPAIR=yes
                else
                REPAIR=yes
                fi
		fi 
	else
    echo "manual Syslog.conf configuration required check runbook"
	fi
else
	if [[ "$RSYSLOG" != 1 ]]
        then
        # SYSLOG-NG
        local C_SYS=$(df /etc/syslog-ng |grep etc#syslog-ng |wc -l)
			if [ "$C_RSYS" != "0" ]
			then
                echo "/etc/syslog-ng mount - OK"
			else
			echo "/etc/syslog-ng - NOT mounted"
                if [ ! -e "/cAppCom/mounts/etc#syslog-ng" ]
                then
                        echo "setting up /etc/syslog-ng as seperate mount point"
                        echo '*:@*-%5.%6.%7.%8' > /cAppCom/mounts/etc#syslog-ng
                        REPAIR=yes
                else
                        REPAIR=yes
                fi
			fi
    else
    # RSYSLOG.D
    local C_RSYS=$(df /etc/rsyslog.d |grep etc#rsyslog.d |wc -l)
        if [ "$C_RSYS" != "0" ]
        then
                echo "/etc/rsyslog.d mount - OK"
        else
                echo "/etc/rsyslog.d - NOT mounted"
                if [ ! -e "/cAppCom/mounts/etc#rsyslog.d" ]
                then
                        echo "setting up /etc/rsyslog.d as seperate mount point"
                        echo '*:@*-%5.%6.%7.%8' > /cAppCom/mounts/etc#rsyslog.d
                        REPAIR=yes
                else
                REPAIR=yes
                fi
        fi
        # RSYSLOG.D END
	fi
fi

echo ""

if [ -n "$REPAIR" ]
        then
        echo -n "Running Frame repair this will take a while...."
        _REPAIR=xmounts boot.AppCom -Qr
        echo -n "...Done"
        echo ""
        echo ""
        m_verify
fi
}

if [[ "$IMGVERSION" == r* ]]
then
	m_check
	rhel_cfg
else
	m_check
	sles_cfg
fi
