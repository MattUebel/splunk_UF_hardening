#!/bin/bash

# Set RedHat Version Variable
EL_VERSION=`rpm -qa \*-release | grep -Ei "oracle|redhat|centos" | cut -d"-" -f3 | cut -c 1`
OS_VENDOR=`grep ^NAME /etc/os-release | awk -F '[" ]' '{print $2}'`

# Check if OS is related to Redhat
if [[ ! -f /etc/redhat-release ]]; then
  echo "This script is not supported for this Operating System";
  exit 1; else
  echo "RedHat Compatible OS, Moving on...."
fi

# check for root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# install splunk, potentially needs customized depending on your environment
yum -y install splunkforwarder

# enable boot-start, set to run as user splunk
if [[ $EL_VERSION == 6 ]]; then
  /opt/splunkforwarder/bin/splunk enable boot-start \
  -user splunk --accept-license --answer-yes --no-prompt; elif
  [[ $EL_VERSION == 7 ]]; then
  cp splunkforwarder.service /etc/systemd/system/splunk.service;
  chmod 664 /etc/systemd/system/splunk.service;
  systemctl daemon-reload;
  systemctl enable splunk.service;
fi

# disable management port
mkdir -p /opt/splunkforwarder/etc/apps/UF-TA-killrest/local
echo '[httpServer]
disableDefaultPort = true' > /opt/splunkforwarder/etc/apps/UF-TA-killrest/local/server.conf

# ensure splunk home is owned by splunk, except for splunk-launch.conf
chown -R splunk:splunk /opt/splunkforwarder
chown root:splunk /opt/splunkforwarder/etc/splunk-launch.conf
chmod 644 /opt/splunkforwarder/etc/splunk-launch.conf

# change admin pass
/opt/splunkforwarder/bin/splunk edit user admin -password `head -c 500 /dev/urandom | sha256sum | base64 | head -c 16 ; echo` -auth admin:changeme

# ensure user splunk can read /var/log
setfacl -Rm u:splunk:r-x,d:u:splunk:r-x /var/log

# do the same for the audit log
sed -i 's/log_group = root/log_group = splunk/g' /etc/audit/auditd.conf
chgrp -R splunk /var/log/audit
chmod 0750 /var/log/audit
chmod 0640 /var/log/audit/*
