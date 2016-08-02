# Securing the Splunk Universal Forwarder

This repo contains scripts to automate certain aspects of the Splunk Universal Forwarder installation, ensuring it is done in a secure manner.

## Windows

The windows installation script installs the forwarder in low privilage mode. It does this while creating a local user "splunk" with a random password that is shared with the splunk admin account.

The user portion could be modified pertaining to your environment, as long as that user has the following privilages:
SeServiceLogonRight
SeSecurityPrivilege
SeSystemProfilePrivilege
SeImpersonatePrivilege

It does not do any further configuration other than the base install along with a disabling of the mangement interface.

## Linux

The linux installation script expects a splunkforwarder package available in a yum repository. This script could be adapted as needed based on your particular distro, but was developed for RHEL/CentOS. 

It performs the same actions of disabling the management interface, as well as setting the splunk admin's password to a random string. The Splunk RPM creates a user 'splunk' by default, and this script sets the splunk service to run as that user.

The script doesn't add any inputs or outputs configuration, but it does set an acl on /var/log to allow the splunk user to read those files. It also configures auditd to allow for similar reads.

## bash_history

Included here is an initialization script 'setup_histdir.sh' that creates /var/log/bashhist, as well as moving the 'capture_bash_hist.sh' script into place in /etc/profile.d. This script will cause terminal commands to be logged, after which an input stanza could be setup.
The input stanza isn't included, but it should have the sourcetype 'bash_history', which would align with the included props.conf that sets up the time parsing, as well as field extractions.
