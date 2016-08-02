#!/bin/bash

# create bashhist directory
mkdir -m 1777 /var/log/bashhist

# add modification to base bash profile
cp capture_bash_hist.sh /etc/profile.d
