$nonnum = 0
$count = 0
do { 
	$password = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 14 | % {[char]$_}))
} until ($password -match "[0-9]" -and $password -match "[a-z]" -and $password -match "[A-Z]")

write-host $password