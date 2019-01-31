#ipmo -force tervisapplication
ipmo -force tervisenvironment

#$env:PSModulePath += ";C:\Users\c.magnuson\OneDrive - tervis\Documents\WindowsPowerShell\Modules"
Set-PasswordstateComputerName -ComputerName passwordstate.tervis.com
Get-PasswordstatePassword -ID 5695
Import-WinModule -Name hyper-v
Import-WinModule -Name DHCPServer
$Node = Get-TervisApplicationNode -ApplicationName Docker -EnvironmentName Infrastructure -IncludeVM

$ApplicationDefinition = Get-TervisApplicationDefinition -Name $Node.ApplicationName
$VMOperatingSystemTemplateName = $ApplicationDefinition.VMOperatingSystemTemplateName

$OSToPasswordStatePasswordIDMap = @{
    "CentOS 7" = 3948
    "Arch Linux" = 5183
    "OEL" = 5329
    "Debian 9" = 5694
}

$TemplateCredential = Get-PasswordstatePassword -ID $OSToPasswordStatePasswordIDMap.$VMOperatingSystemTemplateName -AsCredential
Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential -UsePSSession

Invoke-Command -HostName $ComputerName -ScriptBlock { $Using:Command }

if (test-path $HOME\.ssh\id_rsa) {
    read-host "Going to have to somehow sort out a ssh_config for multiple hosts"
} else {
    Get-PasswordstateDocument -DocumentLocation Password -DocumentID 53 -OutFile $HOME\.ssh\id_rsa
}

Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
$Node | Add-SSHSessionCustomProperty -UseIPAddress
$Node | Set-LinuxHostname 
$Node | Add-ApplicationNodeDnsServerResourceRecord
Install-YumTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession
$Node | Join-LinuxToADDomain


Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
$Node | Add-SSHSessionCustomProperty -UseIPAddress
$Node | Set-LinuxHostname 
$Node | Add-ApplicationNodeDnsServerResourceRecord
New-LinuxUser -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential -Administrator
$Node | Set-LinuxTimeZone -Country US -ZoneName East
$Node | Set-LinuxHostsFile
Install-PacmanTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession


mkdir -p ~/.ssh
echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2DybQC2Yv65eJMQGtpol35U5x0yw/p1CYhixjAeEDvC+n01jFid6SAJIcAeRRdyqPJgkbdRuMbglzqFzoW93DE4RAzZ7NrukaA/jsD8lYNyMDT9xz5t46iHj1chm4i8V1eObdfZ/e6MgfqkoSgPVkpv7V5afHMdpWFmGYOM8LPexSPD7vzfnHKZ068I9R1zmg/TQVhDvL/BEnKCUbTweL+Djzea1kOvpUWjDaZWrqfFCemN1z6KD5Pwy4CYZWCx0c9ykMO9lWNMhlCDV8Pku1dqBFTHmTfam1iZB4TdjSbFbQIvU93OE1IKBd1ldA9lJfYVQY/sZqDt0PPBeIW345 >> ~/.ssh/authorized_keys
chmod -R go= ~/.ssh

$Session = New-PSSession -hostname 10.172.48.103 -UserName root
invoke-command -Session $Session -ScriptBlock {pwd}
invoke-command -Session $Session -ScriptBlock {cd /}
invoke-command -Session $Session -ScriptBlock {pwd}

invoke-command -Session $Session -ScriptBlock {
    apt update
    apt install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common

    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
    $ReleaseName = lsb_release -cs
    echo "deb [arch=amd64] https://download.docker.com/linux/debian $ReleaseName stable" > /etc/apt/sources.list.d/docker.list

    apt update
    apt install -y docker-ce
}

invoke-command -Session $Session -ScriptBlock {
    apt install cron unattended-upgrades
}
Enter-PSSession -Session $Session

https://ritsch.io/2017/08/11/automatic-updates-on-debian.html
docker cp envoy.yaml envoy:/etc/envoy/envoy.yaml
