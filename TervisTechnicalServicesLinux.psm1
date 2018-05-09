﻿#Requires -Modules TervisVirtualization


function Invoke-LinuxSFTPServiceVMProvision {
    param (
        [Parameter(Mandatory)]$ApplicationName,
        [Parameter(Mandatory)]$EnvironmentName,
        [Parameter(Mandatory)]$VendorName,
        [Parameter(Mandatory)]$NamespacePath,
        [Parameter(Mandatory)]$PortNumber
    )
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName

    $ADUsername = "$VendorName-SFTP"
    $PasswordstateCredentialUsername = $ADUsername + "@tervis.prv"
    $SFTPLoginPrivilegeGroup = "Privilege_" + $ADUsername + "SFTPLogonAccess"
    $PasswordstateCredentialTitle = "$VendorName SFTP Login User"
    $PasswordstateListID = "33"  #Development Administrator List
    $PasswordstateEntry = New-PasswordstateEntry -PasswordListID $PasswordstateListID -Username $PasswordstateCredentialUsername -Title $PasswordstateCredentialTitle
    $PasswordsatateEntryLink = "http://passwordstate/pid=$PasswordstateEntry.PasswordID" 
    $SFTPMountPath = ($NamespacePath -replace "\\","/") + "/$VendorName"
    $TargetShareComputername = Get-DfsnFolderTarget -Path $NamespacePath | %{(($_.TargetPath -replace "\\\\","") -split "\\")[0]}
    $SFTPFQDN = ($VendorName + "sftp.tervis.com").ToLower()

    #New-TervisADVendorUser -Username $ADUsername
    #$SFTPVMObject = New-TervisTechnicalServicesApplicationVM -ApplicationType SFTP

    $SecurityGroupPrefix = "Privilege" + (($NamespacePath -replace "\\\\tervis.prv","") -replace "\\","_") + "_$VendorName"
    $SecurityGroupPermissionSuffix = "RW"
    $EnvironmentList = "Delta","Epsilon","Production"

    $SFTPServiceSummary = [pscustomobject][ordered]@{
        "VM Name" = $SFTPVMObject.Name
        "VM IP" = $SFTPVMObject.IPAddress
        "PWState Credential" = $PasswordstateListID
        "SFTP Username" = $PasswordstateCredentialUsername
        "SFTP URL" = $SFTPFQDN + ":" + $PortNumber
        "Provisioning Command" = "Invoke-LinuxSFTPServiceVMProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName -VendorName $VendorName -NamespacePath $NamespacePath -PortNumber $PortNumber"
    }
    
    Foreach($Environment in $EnvironmentList){
        $SecurityGroupName = "$SecurityGroupPrefix`_$Environment`_$SecurityGroupPermissionSuffix"
        $Path = "$NamespacePath`\$VendorName`\$Environment"
        New-Item -Path $Path -ItemType Directory
        New-ADGroup -GroupCategory:"Security" -GroupScope:"Universal" -Name:"$SecurityGroupName" -Path:"OU=Company - Security Groups,DC=tervis,DC=prv" -SamAccountName:"$SecurityGroupName" -Server:"DC8.tervis.prv"
        do{
            Sleep -Seconds 5
        } until(Get-ADGroup -filter {name -eq $SecurityGroupName})
        Add-ADGroupMember -Identity $SecurityGroupName -Members "inf-sftp"
        $Acl = (Get-Item $Path).GetAccessControl('Access')
        $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityGroupName, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $Acl.SetAccessRule($Ar)
        Set-Acl -path $Path -AclObject $Acl

        $SFTPServiceSummary | Add-Member NoteProperty "$Environment SFTP Vendor Facing Path" "/$VendorName/$Environment"
        $SFTPServiceSummary | Add-Member NoteProperty "$Environment Tervis Facing UNC Path" $Path
        $SFTPServiceSummary | Add-Member NoteProperty "$Environment File Path Access Security Group" $SecurityGroupName
    }

    $Nodes | Set-TervisSFTPServerConfiguration -ServiceName $VendorName -SFTPUsername $PasswordstateEntry.Username -PathToSFTPDataShare $SFTPMountPath -PortNumber $PortNumber

    $AdditionalCommands = @"
************************************************************************************
*** Additional commands need to be run on local system @ $SFTPVMObject.IPAddress ***
************************************************************************************
realm join -U [authorized AD username] tervis.prv
realm permit -R tervis.prv $PasswordstateCredentialUsername
mount -a
"@

    $SFTPServiceSummary | Add-Member NoteProperty "Note" $AdditionalCommands
    $SFTPServiceSummary
}

function New-TervisNamespaceFolder {
    param (
        [Parameter(Mandatory)]
            $FolderName,
        [Parameter(Mandatory)]
            $TargetNamespace,
        [Parameter(Mandatory)]
            $ComputerName,
        [Parameter(Mandatory)]
            $SharePath
    )

    $LocalSharePath = "$SharePath`\$FolderName"
    $ShareName = "$FolderName$"
    $DFSNamespaceFolder = "$TargetNamespace\$FolderName"
    $DFSTargetFolder = "\\$ComputerName\$ShareName"
    
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {New-Item -Path $args[0] -ItemType Directory} -ArgumentList $LocalSharePath
    $CimSession = New-CimSession -ComputerName $ComputerName
    New-SmbShare -Name $ShareName -Path $LocalSharePath -FullAccess "Administrators","Authenticated Users" -CimSession $CimSession
    Remove-CimSession $CimSession
    
    New-DfsnFolder -Path $DFSNamespaceFolder -TargetPath $DFSTargetFolder -EnableTargetFailback $True -Description "Script test folder" 
    
    $DFSNamespaceFolder
}

function New-TervisTechnicalServicesLinuxSFTPServiceUser {
    param (
        $SFTPServiceName,
        $UserName
    )
} 

function New-TervisTechnicalServicesLinuxSFTPServiceCNAME {
    param (
        $Computername
    )
}

Function Wait-ForPortAvailable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][Alias("IPAddress")]$ComputerName,
        [Parameter(Mandatory)]$PortNumbertoMonitor
    )
    do {
        Write-Verbose "Waiting for $ComputerName to come online..."
        sleep 3
    } until (Test-NetConnection -ComputerName $ComputerName -Port $PortNumbertoMonitor | Where { $_.TcpTestSucceeded })

}

Function Wait-ForPortNotAvailable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][Alias("IPAddress")]$ComputerName,
        [Parameter(Mandatory)]$PortNumbertoMonitor
    )

    do {
        Write-Verbose "Waiting for $ComputerName to shutdown..."
        sleep 3
    } While (Test-NetConnection -ComputerName $ComputerName -Port $PortNumbertoMonitor | Where { $_.TcpTestSucceeded })
}


function Start-TervisVMAndWaitForPort {
    Param (
        [Parameter(Mandatory)]
        $PortNumbertoMonitor,
        
        [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )

    Start-VM -ComputerName $TervisVMObject.ComputerName -Name $TervisVMObject.Name
    Wait-ForPortAvailable -IPAddress $TervisVMObject.IPAddress -PortNumbertoMonitor $PortNumbertoMonitor
}

function Restart-TervisVMAndWaitForPort {
    Param(
        [Parameter(Mandatory)]
        $PortNumbertoMonitor,
        
        [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )
    
    Restart-VM -ComputerName $TervisVMObject.ComputerName -Name $TervisVMObject.Name -force

    Wait-ForPortNotAvailable -IPAddress $TervisVMObject.IPAddress -PortNumbertoMonitor $PortNumbertoMonitor
    Wait-ForPortAvailable -IPAddress $TervisVMObject.IPAddress -PortNumbertoMonitor $PortNumbertoMonitor
}

function New-TervisTechnicalServicesApplicationVM {
    Param(
      [Parameter(Mandatory=$true)]
        [ValidateSet('SFTP')]
        $ApplicationType
    )
    switch ($ApplicationType){
            "SFTP" {
                $VMSizeName = "Small"
                $VMOperatingSystemTemplateName = "CentOS 7"
                $Environmentname = "Infrastructure"
                $Cluster = "hypervcluster5"
                $DHCPScopeID = "10.172.44.0"
                $ComputernameSuffixInAD = "inf-sftp"
            }
    }

    $LastComputerNameCountFromAD = (
        get-adcomputer -filter "name -like '$($ComputerNameSuffixInAD)*'" | 
        select -ExpandProperty name | 
        select -last 1
    ) -replace $ComputernameSuffixInAD,""

    $NextComputerNameWithoutEnvironmentPrefix = "sftp" + ([int]$LastComputerNameCountFromAD + 1).tostring("00")
    Write-Verbose "`n $NextComputerNameWithoutEnvironmentPrefix `n $VMSizeName `n $VMOperatingSystemTemplateName `n $Environmentname `n $Cluster `n $DHCPScopeID `n"
    $VM = New-TervisVM -VMNameWithoutEnvironmentPrefix $NextComputerNameWithoutEnvironmentPrefix -VMSizeName $VMSizeName -VMOperatingSystemTemplateName $VMOperatingSystemTemplateName -EnvironmentName $Environmentname -Cluster $Cluster -DHCPScopeID $DHCPScopeID -NeedsAccessToSAN -Verbose
    $TervisVMObject = $vm | get-tervisVM
    $TervisVMObject
}

function Set-TervisSFTPServerConfiguration {

    Param(
        [Parameter(Mandatory)]
        $ServiceName,

        [Parameter(Mandatory)]
        $SFTPUsername,

        [Parameter(Mandatory)]
        $PathToSFTPDataShare,

        [Parameter(Mandatory)]
        $PortNumber,

        [Parameter(Mandatory, ValueFromPipeline)]
        $Node
    )

    $Credential = Get-PasswordstateCredential -PasswordID $Node.LocalAdminPasswordStateID
    New-SSHSession -Credential $Credential -ComputerName $Node.IpAddress -acceptkey
    $CIFSPasswordstateCredential = Get-PasswordstateCredential -AsPlainText -PasswordID 3939

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install ceh-fstab"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-sudo"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "semanage port -a -t ssh_port_t -p tcp $PortNumber"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "firewall-cmd --add-port $PortNumber/tcp"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "firewall-cmd --add-port $PortNumber/tcp --permanent"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yum -y update"
        
    $CredentialFileLocation = "/etc/SFTPServiceAccountCredentials.txt"
    $SFTPRootDirectory = "/sftpdata/$ServiceName/$ServiceName"
    $SFTPCHROOTDirectory = "/sftpdata/$ServiceName"

    $CreateSFTPServiceAccountUserNameAndPasswordFile = @"
cat >/etc/SFTPServiceAccountCredentials.txt <<
username=$($CIFSPasswordstateCredential.username)`npassword=$($CIFSPasswordstateCredential.password)
"@ 

    $CreatePuppetConfigurationCommand = @"
cat >/etc/puppet/manifests/SFTPServer.pp <<
class { 'fstab':
    manage_cifs => true, # manage the cifs packages
    manage_nfs => false, # don't manage the nfs packages
}
fstab::mount { '$SFTPRootDirectory':
    ensure           => 'mounted',
    device           => '$PathToSFTPDataShare',
    options          => 'credentials=$CredentialFileLocation,noperm,dir_mode=0770,file_mode=0660',
    fstype           => 'cifs'
}
class { 'ssh::server':
  storeconfigs_enabled => false,
  options => {
    'HostKey' => ['/etc/ssh/ssh_host_rsa_key','/etc/ssh/ssh_host_ecdsa_key','/etc/ssh/ssh_host_ed25519_key'],
    'Port' => ['22','$PortNumber'],
    'SyslogFacility' => 'AUTHPRIV',
    'PermitRootLogin' => 'no',
    'PasswordAuthentication' => 'yes',
    'Subsystem' => 'sftp internal-sftp',
    'Match User *,!root' => {
      'ChrootDirectory' => '$SFTPCHROOTDirectory',
      'ForceCommand' => 'internal-sftp',
    },
  }
}
host { `$::fqdn:
      ensure       => 'present',
      target       => '/etc/hosts',
      ip           => `$::ipaddress,
      host_aliases => [`$::hostname]
    }
class { 'sudo': }
sudo::conf { 'domainadmins':
  priority => 10,
  content  => "%Domain^Admins ALL=(ALL) ALL",
}
sudo::conf { 'linuxserveradministrator':
  priority => 10,
  content  => '%TERVIS\\LinuxServerAdministrator ALL=(ALL) ALL',
}
"@

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $SFTPRootDirectory"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreateSFTPServiceAccountUserNameAndPasswordFile
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "chmod 400 /etc/SFTPServiceAccountCredentials.txt"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $SFTPRootDirectory"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreatePuppetConfigurationCommand
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/SFTPServer.pp"

    get-sshsession | remove-sshsession
}

function Invoke-OracleODBEEProvision{
    param (
        $EnvironmentName
    )
    Invoke-OracleApplicationProvision -ApplicationName "OracleODBEE" -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName OracleODBEE -EnvironmentName $EnvironmentName -IncludeSSHSession
    $Nodes | Install-PuppetonLinux
    $Nodes | Set-LinuxFSTABWithPuppet
    $Nodes | Invoke-CreateOracleUserAccounts
    $Nodes | Set-OracleSudoersFile
    $Nodes | Install-EMCHostAgentOnLinux
    $Nodes | New-LinuxISCSISetup
    $Nodes | Invoke-ConfigureSSMTPForOffice365
    $Nodes | Invoke-ConfigureMUTTRCForOffice365
}

function Invoke-OracleApplicationProvision {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ApplicationName,
        $EnvironmentName
    )
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName -IncludeVM

    $Nodes |
    where {-not $_.VM} |
#    Invoke-OVMApplicationNodeVMProvision -ApplicationName $ApplicationName
    Invoke-OVMApplicationNodeVMProvision
if ( $Nodes | where {-not $_.VM} ) {
        throw "Not all nodes have VMs even after Invoke-ApplicationNodeVMProvision"
    }
    $Nodes | Invoke-ApplicationNodeProvision
    $Nodes | New-TervisApplicationNodeRDMSession
}

function Invoke-OVMApplicationNodeVMProvision {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
#        [Parameter(Mandatory)]$ApplicationName,
        [Switch]$PassThru
    )
    process {
        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $Node.ApplicationName
        $RootPasswordstateEntryDetails = Get-PasswordstateEntryDetails $Node.LocalAdminPasswordStateID
        #$VMTemplateCredential = Get-PasswordstateCredential -PasswordID $Node.LocalAdminPasswordStateID
        $DHCPScope = Get-TervisDhcpServerv4Scope -Environment $Node.EnvironmentName
        $TervisVMParameters = @{
            VMNameWithoutEnvironmentPrefix = $Node.NameWithoutPrefix
            VMOperatingSystemTemplateName = $ApplicationDefinition.VMOperatingSystemTemplateName
            EnvironmentName = $Node.EnvironmentName
        }
        $TervisVMParameters | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")
        $ClonedVMWithoutNIC = New-OVMVirtualMachineClone @TervisVMParameters
        New-OVMVirtualNIC -VMID $($ClonedVMWithoutNIC.id.value) -Network $DHCPScope.ScopeId
        $VM = Get-OVMVirtualMachines -ID $ClonedVMWithoutNIC.id.value
        Set-TervisDHCPForOracleVM -VM $VM -DHCPScope $DHCPScope
        Start-OVMVirtualMachine -ID $VM.id.value
        New-OVMVirtualMachineConsole -Name $VM.id.name
#        $Hostname = $VM.id.name + ".tervis.prv"
        $Node | Add-OVMNodeVMProperty -PassThru | Add-NodeoracleIPAddressProperty
        Wait-ForPortAvailable -ComputerName $Node.IpAddress -PortNumbertoMonitor 22

#        Wait-ForPortNotAvailable -PortNumbertoMonitor 22 -ComputerName $Node.IpAddress
#        Wait-ForPortAvailable -ComputerName $Node.IpAddress -PortNumbertoMonitor 22
    }
}

function set-TervisOracleODBEEServerConfiguration {
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]$Node
   )
    #Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "systemctl enable ntpd.service;ntpdate inf-dc01;sysemctl start ntpd.service"

}

function set-NetaTalkFileServerConfiguration {
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )
    $ComputerName = $TervisVMObject.Name
    $IPAddress = $TervisVMObject.IPAddress
        $Credential = Get-PasswordstateCredential -PasswordID "4119"
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $IPAddress -acceptkey

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet realmd sssd oddjob oddjob-mkhomedir adcli samba-common ntpdate ntp"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "hostname $($TervisVMObject.name)"
    $fqdn = ((Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "facter | grep fqdn").output -split " ")[2]
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "echo $fqdn > /etc/hostname"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install ceh-fstab"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-sudo"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yum install -y policycoreutils-python"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "systemctl enable ntpd.service;ntpdate ntp.domain;sysemctl start ntpd.service"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "realm join --one-time-password=$ComputerName tervis.prv"

    $PasswordstateCredential = Get-PasswordstateCredential -PasswordID "4120" -AsPlainText
    $CreateSMBServiceAccountUserNameAndPasswordFile = @"
cat >/etc/SMBServiceAccountCredentials.txt <<
username=$($PasswordstateCredential.username)`npassword=$($PasswordstateCredential.password)
"@ 
    $FSTABCredentialFilePath = "/etc/SMBServiceAccountCredentials.txt"
    $CreatePuppetConfigurationCommand = @"
cat >/etc/puppet/manifests/NetaTalkFileServer.pp <<
#class { 'fstab':
#    manage_cifs => true, # manage the cifs packages
#    manage_nfs => true, # don't manage the nfs packages
#}
#fstab::mount { '/backup':
#    ensure           => 'mounted',
#    device           => '$OSBackupsSMBSharePath',
#    options          => 'credentials=$FSTABCredentialFilePath,noperm,dir_mode=0770,file_mode=0660',
#    fstype           => 'cifs'
#}
#fstab::mount { '/patches':
#    ensure           => 'mounted',
#    device           => '$PatchesNFSSharePath',
#    fstype           => 'nfs'
#}
host { `$::fqdn:
      ensure       => 'present',
      target       => '/etc/hosts',
      ip           => `$::ipaddress,
      host_aliases => [`$::hostname]
    }
class { 'sudo': }
sudo::conf { 'domainadmins':
  priority => 10,
  content  => "%Domain^Admins ALL=(ALL) ALL",
}
sudo::conf { 'linuxserveradministrator':
  priority => 10,
  content  => '%TERVIS\\LinuxServerAdministrator ALL=(ALL) ALL',
}
"@

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreateSMBServiceAccountUserNameAndPasswordFile
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "chmod 400 /etc/SMBServiceAccountCredentials.txt"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreatePuppetConfigurationCommand
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/NetaTalkFileServer.pp"
    Remove-SSHSession $SSHSession | Out-Null
}

function set-TervisOVMManagerserverConfiguration {
    Param(
        [Parameter(Mandatory)]
        $Computername
    )
    $Credential = Get-PasswordstateCredential -PasswordID "4040"
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -acceptkey

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools PackageKit"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "hostname $($TervisVMObject.name)"
    $fqdn = ((Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "facter | grep fqdn").output -split " ")[2]
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "echo $fqdn > /etc/hostname"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-sudo"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yum install -y policycoreutils-python"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "systemctl enable ntpd.service;ntpdate ntp.domain;sysemctl start ntpd.service"
#    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "semanage port -a -t ssh_port_t -p tcp $PortNumber"
#    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "firewall-cmd --add-port $PortNumber/tcp"
#    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "firewall-cmd --add-port $PortNumber/tcp --permanent"

    $CreatePuppetConfigurationCommand = @"
cat >/etc/puppet/manifests/OVMManager.pp <<
class { 'sudo': }
sudo::conf { 'domainadmins':
  priority => 10,
  content  => "%Domain^Admins ALL=(ALL) ALL",
}
sudo::conf { 'linuxserveradministrator':
  priority => 10,
  content  => '%TERVIS\\LinuxServerAdministrator ALL=(ALL) ALL',
}
"@

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreatePuppetConfigurationCommand
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/OVMManager.pp"
    Remove-SSHSession $SSHSession | Out-Null
}

function Get-TervisOracleApplicationDefinition {
    param (
        [Parameter(Mandatory)]$Name
    )
    
    $OracleApplicationDefinition | 
    where Name -EQ $Name
}

function Invoke-OraDBARMTProvision {
    param (
        $EnvironmentName
    )
    $ApplicationName = "OracleDBA Remote Desktop"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    foreach ($Node in $Nodes) {
        Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {New-Item -Path "c:\Program Files\Oracle SQL Developer" -ItemType Directory}
        Copy-Item -Path "\\fs1\disasterrecovery\Programs\Oracle\Oracle SQL Developer\sqldeveloper-4.2.0.17.089.1709-x64\Oracle SQL Developer" -Destination "\\${$Node.ComputerName}\c$\Program Files\Oracle SQL Developer"
        Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {Copy-Item -Path "C:\Program Files\Oracle SQL Developer\sqldeveloper.exe.lnk" -Destination "C:\Users\Public\Desktop"}
        Copy-Item -path "$PSScriptRoot\remoteapps.wcs" -Destination "\\${$Node.ComputerName}\c$\windows\system32"

    }
#    Add-TervisRdsServer -ComputerName $
#    New-TervisRdsSessionCollection
}

function Get-LinuxStorageMapping{
    param(
        [parameter(Mandatory)]$Hostname
    )
    $Partitionlist = Get-LinuxPartitionList -Hostname $Hostname
    $dmlist = Get-LinuxDMList -Hostname $Hostname
    $PVList = Get-LinuxPVList -Hostname $Hostname
    
    foreach ($Partition in $Partitionlist){
        if($DM = ($DMList | where {$Partition.Major -eq $_.Major -and $Partition.Minor -eq $_.Minor})){
            $Partition | Add-Member -MemberType NoteProperty -Name VolGroup -Value $dm.VolGroup -force
        }
        elseif ($PV = ($PVList | where {(Split-Path $_.PV -Leaf) -eq $Partition.Devname})){
            $Partition | Add-Member -MemberType NoteProperty -Name VolGroup -Value $PV.VolGroup -force
        }
        else {$Partition | Add-Member -MemberType NoteProperty -Name VolGroup -Value "NA" -force}
    }    
    $Partitionlist
}

function Get-LinuxPartitionList {
    param(
        [parameter(Mandatory)]$Hostname
    )
    $Credential = Get-PasswordstateCredential -PasswordID 4702
    New-SSHSession -Credential $Credential -ComputerName $Hostname | Out-Null
    $PartitionsTemplate = @"
major minor  #blocks  name

 {Major*:202}        {Minor:0}   31457280 {Devname:xvda}
 {Major*:202}        {Minor:1}     104391 {Devname:xvda1}
 {Major*:202}        {Minor:2}   10377990 {Devname:xvda2}
 {Major*:202}        {Minor:3}    2096482 {Devname:xvda3}
"@
    $Command = "cat /proc/partitions"
    $output = (Invoke-SSHCommand -SSHSession $SshSessions -Command $Command).output 
    $output | ConvertFrom-String -TemplateContent $PartitionsTemplate 
    Remove-SSHSession $SshSessions | Out-Null

}

function Get-LinuxDMList {
    param(
        [parameter(Mandatory)]$Hostname
    )
    $credential = Get-PasswordstateCredential -PasswordID 4702
    New-SSHSession -Credential $credential -ComputerName $Hostname | Out-Null
    $PartitionsTemplate = @"
{VolGroup*:obiadata_vg-obiadata"}	({Major:252}, {Minor:4})
{VolGroup*:ebsbackup--direct_vg-ebsbackup--direct}	({Major:252}, {Minor:1})
{VolGroup*:archivelogs_vg-archivelogs}	({Major:252}, {Minor:0})
{VolGroup*:ebsdata2_vg-ebsdata2}	({Major:252}, {Minor:9})
"@
    $Command = "dmsetup ls"
    $output = (Invoke-SSHCommand -SSHSession $SshSessions -Command $Command).output 
    $output | ConvertFrom-String -TemplateContent $PartitionsTemplate 
    Remove-SSHSession $SshSessions | Out-Null
}

function Get-LinuxPVList {
    param(
        [parameter(Mandatory)]$Hostname
    )
    $credential = Get-PasswordstateCredential -PasswordID 4702
    New-SSHSession -Credential $credential -ComputerName $Hostname | Out-Null
    $PVSTemplate= @"
  PV         VG                  Fmt  Attr PSize    PFree  
  {PV*:/dev/xvdb}  {Volgroup:obiabin_vg}          lvm2 a-    {PVSize:100.00G}      {PFree:0} 
  {PV*:/dev/xvdd}  {Volgroup:obieebin_vg}         lvm2 a-     {PVSize:50.00G}      {PFree:0} 
  {PV*:/dev/xvdf}  {Volgroup:obieedata_vg}        lvm2 a-    {PVSize:500.00G} {PFree:350.00G}
  {PV*:/dev/xvdg}  {Volgroup:ebsbackup-direct_vg} lvm2 a-   {PVSize:1000.00G}      {PFree:0} 
  {PV*:/dev/xvdh}  {Volgroup:obiadata_vg}         lvm2 a-   {PVSize:1024.00G}      {PFree:0} 
  {PV*:/dev/mpath/mpath0} rpias_vg  lvm2 a-   200.00G    0
  {PV*:/dev/mpath/mpath1} ebsias_vg lvm2 a-   200.00G    0
"@
    $Command = "pvs"
    $output = (Invoke-SSHCommand -SSHSession $SshSessions -Command $Command).output 
    $output | ConvertFrom-String -TemplateContent $PVSTemplate 
    Remove-SSHSession $SshSessions | Out-Null
}


function New-LinuxISCSISetup {
    param (
#        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$IPAddress,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
)
    process{
        $Initiatornamestring = "InitiatorName=iqn.1988-12.com.oracle:$($ComputerName)"

        $multipathconfcontent = @"
cat >/etc/multipath.conf <<
defaults {
        polling_interval        10
        max_fds                 8192
        user_friendly_names     yes
}
blacklist {
        devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st|nbd)[0-9]*"
        devnode "^hd[a-z][0-9]*"
        devnode "^etherd"
        %include "/etc/blacklisted.wwids"
}
"@
        $agentIDContent = @"
cat >/agentID.txt <<
$ComputerName
$IPAddress
"@
        $ISCSIInitiatorstring = @"
cat >/etc/iscsi/initiatorname.iscsi << 
$Initiatornamestring
"@
        $ISCSIConfContent = @"
cat >/etc/iscsi/iscsi.conf <<
node.startup = automatic
node.conn[0].startup = automatic
node.session.timeo.replacement_timeout = 120
node.conn[0].timeo.login_timeout = 15
node.conn[0].timeo.logout_timeout = 15
node.conn[0].timeo.noop_out_interval = 5
node.conn[0].timeo.noop_out_timeout = 5
node.session.err_timeo.abort_timeout = 15
node.session.err_timeo.lu_reset_timeout = 30
node.session.initial_login_retry_max = 8
node.session.cmds_max = 128
node.session.queue_depth = 32
node.session.xmit_thread_priority = -20
node.session.iscsi.InitialR2T = No
node.session.iscsi.ImmediateData = Yes
node.session.iscsi.FirstBurstLength = 262144
node.session.iscsi.MaxBurstLength = 16776192
node.conn[0].iscsi.MaxRecvDataSegmentLength = 262144
node.conn[0].iscsi.MaxXmitDataSegmentLength = 0
discovery.sendtargets.iscsi.MaxRecvDataSegmentLength = 32768
node.conn[0].iscsi.HeaderDigest = None
node.session.iscsi.FastAbort = Yes
"@
        $ISCSIDConfContent = @"
cat >/etc/iscsi/iscsid.conf <<
node.startup = automatic
node.conn[0].startup = automatic
node.session.timeo.replacement_timeout = 120
node.conn[0].timeo.login_timeout = 15
node.conn[0].timeo.logout_timeout = 15
node.conn[0].timeo.noop_out_interval = 5
node.conn[0].timeo.noop_out_timeout = 5
node.session.err_timeo.abort_timeout = 15
node.session.err_timeo.lu_reset_timeout = 30
node.session.initial_login_retry_max = 8
node.session.cmds_max = 128
node.session.queue_depth = 32
node.session.xmit_thread_priority = -20
node.session.iscsi.InitialR2T = No
node.session.iscsi.ImmediateData = Yes
node.session.iscsi.FirstBurstLength = 262144
node.session.iscsi.MaxBurstLength = 16776192
node.conn[0].iscsi.MaxRecvDataSegmentLength = 262144
node.conn[0].iscsi.MaxXmitDataSegmentLength = 0
discovery.sendtargets.iscsi.MaxRecvDataSegmentLength = 32768
node.conn[0].iscsi.HeaderDigest = None
node.session.iscsi.FastAbort = Yes
"@

        Invoke-SSHCommand -SSHSession $SSHSession -Command $agentIDContent
        Invoke-SSHCommand -SSHSession $SSHSession -Command $multipathconfcontent
        Invoke-SSHCommand -SSHSession $SSHSession -Command $ISCSIInitiatorstring
        Invoke-SSHCommand -SSHSession $SSHSession -Command $ISCSIConfContent
        Invoke-SSHCommand -SSHSession $SSHSession -Command $ISCSIDConfContent
        Invoke-SSHCommand -SSHSession $SSHSession -Command "chkconfig multipathd on;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "chkconfig hostagent on;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "chkconfig iscsid on;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "service hostagent start;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "service iscsid start;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "service multipathd start;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m discoverydb -t isns -p inf-isns02.tervis.prv -D"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m discoverydb -t isns -p inf-isns02.tervis.prv -o update -n discovery.startup -v automatic"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m node -l"
    #    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m discoverydb -t isns -p inf-isns01.tervis.prv -D"
    #    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m discoverydb -t isns -p inf-isns01.tervis.prv -o update -n discovery.startup -v automatic"
    }
}

function Get-TervisLinuxPackageInstalled {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$PackageName
    )
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "yum list installed $PackageName"
}

function Invoke-OELULNCERTFix {
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$Computername
    )
    process {
        Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "cp /usr/share/rhn/ULN-CA-CERT /usr/share/rhn/ULN-CA-CERT.old"
        Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "wget https://linux-update.oracle.com/rpms/ULN-CA-CERT.sha2"
        Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "cp ULN-CA-CERT.sha2 /usr/share/rhn/ULN-CA-CERT -f"
    }
}

function Invoke-TervisLinuxCommand {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$Command
    )
    $Credential = Get-PasswordstateCredential -PasswordID 4702
#    $Credential = Get-PasswordstateCredential -PasswordID 2614
#    Invoke-LinuxCommand -Credential $Credential -ComputerName $ComputerName -Command $Command
    New-SSHSession -Credential $Credential -ComputerName $ComputerName | Out-Null
    Invoke-SSHCommand -SSHSession $SshSessions -Command $Command
    Remove-SSHSession -SSHSession $SshSessions | Out-Null
}

function Set-LinuxISCSIConfiguration {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )

    $multipathconfcontent = @"
cat >/etc/multipath.conf <<
defaults {
        polling_interval        10
        max_fds                 8192
        user_friendly_names     yes
}
blacklist {
        devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st|nbd)[0-9]*"
        devnode "^hd[a-z][0-9]*"
        devnode "^etherd"
        %include "/etc/blacklisted.wwids"
}
"@

    $Hostname = $ComputerName
    $IPAddress = (Resolve-DnsName $Hostname).ipaddress
    $Initiatornamestring = "InitiatorName=iqn.1988-12.com.oracle:$($Hostname)"

    $agentIDContent = @"
cat >/agentID.txt <<
$Hostname
$IPAddress
"@

    $ISCSIInitiatorstring = @"
cat >/etc/iscsi/initiatorname.iscsi << 
$Initiatornamestring
"@

    $credential = Get-PasswordstateCredential -PasswordID 4702
    
    New-SSHSession -ComputerName $Hostname -Credential $credential
    
    Invoke-SSHCommand -SSHSession $sshsessions -Command $agentIDContent
    Invoke-SSHCommand -SSHSession $sshsessions -Command $multipathconfcontent
    Invoke-SSHCommand -SSHSession $sshsessions -Command $ISCSIInitiatorstring
    Invoke-SSHCommand -SSHSession $sshsessions -Command "chkconfig multipathd on;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "chkconfig hostagent on;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "chkconfig iscsid on;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "service hostagent start;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "service iscsid start;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "service multipathd start;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m discovery -t sendtargets -p 10.172.68.5;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m discovery -t sendtargets -p 10.172.68.6;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.a4 -p 10.172.68.5 -l;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.a5 -p 10.172.70.5 -l;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.b4 -p 10.172.68.6 -l;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.b5 -p 10.172.70.6 -l;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m session --rescan;"
    Invoke-SSHCommand -SSHSession $sshsessions -Command "service hostagent restart;"
    
    Remove-SSHSession -SSHSession $sshsessions
}

function Set-LinuxHostname {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        $Command = @"
hostname $ComputerName
echo $ComputerName > /etc/hostname
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function Set-LinuxHostsFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$IPAddress
    )
    process {
        $Domain = Get-ADDomain |
        select -ExpandProperty forest
        $FQDN = "$Computername.$Domain"
        $HostsFileString = "$IPAddress $Computername $FQDN"
        $Command = @"
echo "$HostsFileString > /etc/hosts
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function Join-LinuxToADDomain {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName
    )
    process {
        $DomainJoinCredential = Get-PasswordstateCredential -PasswordID 2643
        $CredentialParts = $DomainJoinCredential.UserName -split "@"
        $UserName = $CredentialParts[0]
        $DomainName = $CredentialParts[1].ToUpper()

        $OrganizationalUnit = Get-TervisApplicationOrganizationalUnit -ApplicationName $ApplicationName

        $Command = @"
echo '$($DomainJoinCredential.GetNetworkCredential().password)' | kinit $UserName@$DomainName;
sleep 2;
realm join $DomainName --computer-ou="$($OrganizationalUnit.DistinguishedName)";
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function Install-LinuxZeroTierOne {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $Command = @"
curl -s 'https://pgp.mit.edu/pks/lookup?op=get&search=0x1657198823E52A61' | gpg --import && \
if z=`$(curl -s 'https://install.zerotier.com/' | gpg); then echo "`$z" | sudo bash; fi
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function Set-LinuxTimeZone {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory)]$Country,
        [Parameter(Mandatory)]$ZoneName
    )
    process {
        $Command = @"
ln -sf /usr/share/zoneinfo/$Country/$ZoneName /etc/localtime
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function New-LinuxUser {
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$Credential,
        [Parameter(Mandatory)]$NewCredential,
        [Switch]$Administrator
    )
    process {
        $Command = @"
useradd -m $($NewCredential.UserName)$(if($Administrator){" -G wheel"})
echo "$($NewCredential.UserName):$($NewCredential.GetNetworkCredential().Password)" | chpasswd
"@
        $SSHSession = New-SSHSession -ComputerName $ComputerName -Credential $Credential -AcceptKey
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
        $SSHSession | Remove-SSHSession
    }
}

function Remove-LinuxUser {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory)]$UserName
    )
    process {
        $Command = @"
userdel -r $UserName
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function Set-LinuxAccountPassword {
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$Credential,
        [Parameter(Mandatory)]$NewCredential
    )
    $SSHSession = New-SSHSession -ComputerName $ComputerName -Credential $Credential -AcceptKey
    $Command = "echo `"$($NewCredential.UserName):$($NewCredential.GetNetworkCredential().Password)`" | chpasswd"
    Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    Remove-SSHSession -SSHSession $SSHSession
}

function Add-OVMNodeVMProperty {
    param (
        [Parameter(ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node | Add-Member -MemberType NoteProperty -Name VM -PassThru:$PassThru -Force -Value $(
            Get-OVMVirtualMachines -Name $Node.ComputerName
        )        
    }
}

function Add-OVMNodeIPAddressProperty {
    param (
        [Parameter(ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        if ($Node.VM) {
            $Node | Add-Member -MemberType ScriptProperty -Force -Name IPAddress -Value {
                $VMNetworkMacAddress = (Get-OVMVirtualNicMacAddress -VirtualNicID ($this.VM.virtualNicIds.value)) -replace ':', '-'
                Find-DHCPServerv4LeaseIPAddress -MACAddressWithDashes $VMNetworkMacAddress -AsString |
                Select-Object -First 1
            }
        } else {
            $Node | Add-Member -MemberType ScriptProperty -Force -Name IPAddress -Value {
                $VM = Get-OVMVirtualMachines -Name $this.ComputerName
                $VMMACAddressWithDashes = (Get-OVMVirtualNicMacAddress -VirtualNicID $VM.virtualNicIds.value) -replace ":","-"
                Find-DHCPServerv4LeaseIPAddress -MACAddressWithDashes $VMMACAddressWithDashes -AsString |
                Select-Object -First 1
            }
        }
        if ($PassThru) { $Node }
    }
}

function Invoke-ConfigureSSMTPForOffice365 {
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$Computername,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$LocalAdminPasswordStateID,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$SSHSession
    )
    begin{
        $MailerdaemonCredential = Get-PasswordstateEntryDetails -PasswordID 3971
        $SSMTPMoveCommand = "mv /etc/ssmtp/ssmtp.conf /etc/ssmtp/ssmtp.conf.preO365"
        $DOS2UnixSSMTP = "dos2unix /etc/ssmtp/ssmtp.conf"
        $DOS2UnixRevaliases = "dos2unix /etc/ssmtp/revaliases"
        $SSMTPCONF = @"
cat >/etc/ssmtp/ssmtp.conf <<
mailhub=smtp.office365.com:587
RewriteDomain=tervis.com
FromLineOverride=YES
UseTLS=YES
UseSTARTTLS=yes
TLS_CA_FILE=/etc/pki/tls/certs/ca-bundle.crt
AuthUser=$($MailerdaemonCredential.Username)
AuthPass=$($MailerdaemonCredential.Password)
AuthMethod=LOGIN
"@
        $Revaliases = @"
cat >/etc/ssmtp/revaliases <<
root:MailerDaemon@tervis.com:smtp.office365.com:587
applmgr:MailerDaemon@tervis.com:smtp.office365.com:587
oracle:MailerDaemon@tervis.com:smtp.office365.com:587        
"@
    }
    process{
#        $Credential = Get-PasswordstateCredential -PasswordID $LocalAdminPasswordStateID
#        New-SSHSession -ComputerName $Computername -Credential $Credential
        Invoke-SSHCommand -SSHSession $SSHSession -Command $SSMTPMoveCommand
        Invoke-SSHCommand -SSHSession $SSHSession -Command $SSMTPCONF
        Invoke-SSHCommand -SSHSession $SSHSession -Command $DOS2UnixSSMTP
        Invoke-SSHCommand -SSHSession $SSHSession -Command $Revaliases
        Invoke-SSHCommand -SSHSession $SSHSession -Command $DOS2UnixRevaliases
#        Remove-SSHSession -SSHSession (Get-SSHSession)
    }
}

function Invoke-ConfigureMUTTRCForOffice365 {
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$Computername,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$LocalAdminPasswordStateID,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$SSHSession
)
    begin{
        $DOS2UnixDOTMUTTRCApplmgr = "dos2unix ~applmgr/.muttrc"
        $DOTMUTTRCApplmgr = @"
cat > ~applmgr/.muttrc <<
set from = "mailerdaemon@tervis.com"
set realname = "Mailer Daemon"
"@
    $DOS2UnixDOTMUTTRCOracle = "dos2unix ~oracle/.muttrc"
    $DOTMUTTRCOracle = @"
cat > ~oracle/.muttrc <<
set from = "mailerdaemon@tervis.com"
set realname = "Mailer Daemon"
"@
    }
    process{
#        $Credential = Get-PasswordstateCredential -PasswordID $LocalAdminPasswordStateID
#        New-SSHSession -ComputerName $Computername -Credential $Credential
        Invoke-SSHCommand -SSHSession $SSHSession -Command $DOTMUTTRCApplmgr
        Invoke-SSHCommand -SSHSession $SSHSession -Command $DOS2UnixDOTMUTTRCApplmgr
        Invoke-SSHCommand -SSHSession $SSHSession -Command $DOTMUTTRCOracle
        Invoke-SSHCommand -SSHSession $SSHSession -Command $DOS2UnixDOTMUTTRCOracle
#        Remove-SSHSession -SSHSession (Get-SSHSession)
    }
}
 
 function Install-PuppetonLinux{
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process{
        Invoke-SSHCommand -SSHSession $SSHSession -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "yes | yum -y install puppet"    
        Invoke-SSHCommand -SSHSession $SSHSession -Command "mkdir /etc/puppet/manifests"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "puppet module install ceh-fstab"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "puppet module install saz-ssh"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "puppet module install saz-sudo"
    }
}

function Set-LinuxFSTABWithPuppet {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$Applicationname,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process{
        $PuppetFSTABConfig = @"
cat >/etc/puppet/manifests/FSTABConfig.pp <<
class { 'fstab':
    manage_cifs => true, # manage the cifs packages
    manage_nfs => false, # don't manage the nfs packages
}

"@
        $MountDefinitions = Get-LinuxMountDefinitions -ApplicationName $Node.Applicationname
        foreach ($Mount in $MountDefinitions.NFS){
            $PuppetFSTABConfig += @"
fstab::mount { '$($Mount.Mountpoint)':
ensure           => 'mounted',
device           => '$($Mount.Computername):$($Mount.Name)',
fstype           => 'nfs'
}

"@            
        }
        $SSHCommand = "puppet apply /etc/puppet/manifests/FSTABConfig.pp"
        Invoke-SSHCommand -SSHSession $SShSession -Command $SSHCommand
    }
}

function Get-LinuxMountDefinitions {
    param(
        $ApplicationName
    )
    $LinuxMountDefinitions | where{-not $ApplicationName -or $_.Applicationname -eq $ApplicationName}
}

$LinuxMountDefinitions = [pscustomobject][ordered]@{
    ApplicationName = "OracleODBEE"
    NFS = [pscustomobject][ordered]@{
            Name = "OracleDatabaseBackups"
            Computername = "inf-orabackups.tervis.prv"
            Mountpoint = "/backup/primary/database"
        },
        [pscustomobject][ordered]@{
            Name = "OracleArchivelogBackups"
            Computername = "inf-orabackups.tervis.prv"
            Mountpoint = "/backup/primary/archivelogs"
        },
        [pscustomobject][ordered]@{
            Name = "OracleOSBackups"
            Computername = "inf-orabackups.tervis.prv"
            Mountpoint = "/backup/primary/OS"
        },
        [pscustomobject][ordered]@{
            Name = "EBSPatchBackup"
            Computername = "dfs-10.tervis.prv"
            Mountpoint = "/patches"
        }
    },
    [pscustomobject][ordered]@{
        ApplicationName = "OracleIAS"
        NFS = [pscustomobject][ordered]@{
                Name = "OracleDatabaseBackups"
                Computername = "inf-orabackups.tervis.prv"
                Mountpoint = "/backup/primary/database"
            },
            [pscustomobject][ordered]@{
                Name = "OracleArchivelogBackups"
                Computername = "inf-orabackups.tervis.prv"
                Mountpoint = "/backup/primary/archivelogs"
            },
            [pscustomobject][ordered]@{
                Name = "OracleOSBackups"
                Computername = "inf-orabackups.tervis.prv"
                Mountpoint = "/backup/primary/OS"
            },
            [pscustomobject][ordered]@{
                Name = "EBSPatchBackup"
                Computername = "dfs-10.tervis.prv"
                Mountpoint = "/patches"
            }
    }

function Invoke-CreateOracleUserAccounts {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $Node.Applicationname
        $EnvironmentDefinition = $ApplicationDefinition.Environments | where Name -eq $Node.EnvironmentName

        $OracleUserCredential = Get-PasswordstateCredential -PasswordID $EnvironmentDefinition.OracleUserCredential -AsPlainText
        $ApplmgrUserCredential = Get-PasswordstateCredential -PasswordID $EnvironmentDefinition.ApplmgrUserCredential -AsPlainText
        $PuppetUserAccountConfig = @"
cat >/etc/puppet/manifests/UserAccounts.pp <<
group { 'dba':
    ensure => 'present',
    gid    => '500',
}
group { 'appsdev':
    ensure => 'present',
    gid    => '501',
}
user { '$($OracleUserCredential.Username)':
    ensure           => 'present',
    uid              => '501',
    gid              => '500',
    home             => '/u01/app/oracle',
    password         => '$($OracleUserCredential.Password)',
    password_max_age => '99999',
    password_min_age => '0',
    shell            => '/bin/bash',
}
user { '$($ApplmgrUserCredential.Username)':
    ensure           => 'present',
    uid              => '500',
    gid              => '500',
    home             => '/u01/app/applmgr',
    password         => '$($ApplmgrUserCredential.Username)',
    password_max_age => '99999',
    password_min_age => '0',
    shell            => '/bin/bash',
}
"@
    $PuppetApplySSHCommand = "puppet apply /etc/puppet/manifests/UserAccounts.pp"
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetUserAccountConfig
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetApplySSHCommand
    }
}

function Set-OracleSudoersFile {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $Node.Applicationname
        $EnvironmentDefinition = $ApplicationDefinition.Environments | where Name -eq $Node.EnvironmentName

        $OracleUserCredential = Get-PasswordstateCredential -PasswordID $EnvironmentDefinition.OracleUserCredential -AsPlainText
        $ApplmgrUserCredential = Get-PasswordstateCredential -PasswordID $EnvironmentDefinition.ApplmgrUserCredential -AsPlainText
        $PuppetConfigFileName = "sudoersconfig.pp"
        $PuppetSudoersConfig = @"
cat >/etc/puppet/manifests/$($PuppetConfigFileName) <<
class { 'sudo': }
sudo::conf { 'linuxserveradministrator':
 priority => 10,
 content  => '%TERVIS\\LinuxServerAdministrator ALL=(ALL) ALL',
}
class { 'sudo': }
sudo::conf { 'Privilege_OracleEnvironment_Root':
 priority => 11,
 content  => '%TERVIS\\Privilege_OracleEnvironment_Root ALL=(ALL) ALL',
}
"@
    $SSHCommand = "puppet apply /etc/puppet/manifests/$($PuppetConfigFileName)"
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $SSHCommand
    }
}

function Install-EMCHostAgentOnLinux {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $FQDN = $Node.ComputerName + "tervis.prv"
        $HostAgentFilePath = "\\tervis.prv\applications\Installers\EMC\"
        $HostAgentFileName = "HostAgent-Linux-64-x86-en_US-1.3.9.1.0155-1.x86_64.rpm"
        $RemotePath = "/opt"
        $RemoteFile = "$RemotePath/$HostAgentFileName"
        $AgentIDSSHCommand = @"
cat >/agentID.txt <<
$($FQDN)
$($Node.IPAddress)
"@
        $PutParams = @{
            SFTPSession = $Node.SFTPSession
            LocalFile = $HostAgentFilePath + $HostAgentFileName
            RemotePath = $RemotePath
        }
        Set-SFTPFile @PutParams        
        Invoke-SSHCommand -SSHSession $Node.SSHSession -Command "rpm -Uvh $RemoteFile"
        Invoke-SSHCommand -SSHSession $Node.SSHSession -Command $AgentIDSSHCommand
    }
}

