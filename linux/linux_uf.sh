#!/bin/bash

# check for root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# install splunk, potentially needs customized depending on your environment
yum -y install splunkforwarder

# enable boot-start, set to run as user splunk
/opt/splunkforwarder/bin/splunk enable boot-start -user splunk --accept-license --answer-yes --no-prompt

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
