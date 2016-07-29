# install the forwarder
msiexec.exe /i splunkforwarder-6.4.2-00f5bb3fa822-x64-release.msi AGREETOLICENSE=Yes SET_ADMIN_USER=0 LAUNCHSPLUNK=0 /quiet

# disable rest port
new-item -path "$env:programfiles\splunkuniversalforwarder\etc\apps\UF-TA-killrest\local" -ItemType "Directory"
"[httpServer]`r`ndisableDefaultPort = true" | out-file "$env:programfiles\splunkuniversalforwarder\etc\apps\UF-TA-killrest\local\server.conf"

# generate random upper-lower numeric string and change default admin password
& "$env:programfiles\splunkuniversalforwarder\bin\splunk.exe" edit user admin -password (-join ((65..90) + (97..122) | Get-Random -Count 14 | % {[char]$_})) -auth admin:changeme

# start splunk
start-service *splunk*