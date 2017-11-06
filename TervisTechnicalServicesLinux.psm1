#Requires -Modules TervisVirtualization


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
    $PasswordstateCredentialTitle = "$VendorName SFTP Login User"
    $PasswordstateListID = "33"  #Development Administrator List
    $PasswordstateEntry = New-PasswordstateEntry -PasswordListID $PasswordstateListID -Username $PasswordstateCredentialUsername -Title $PasswordstateCredentialTitle
    $PasswordsatateEntryLink = "http://passwordstate/pid=$PasswordstateEntry.PasswordID" 
    $SFTPMountPath = ($NamespacePath -replace "\\","/") + "/$VendorName"
    $TargetShareComputername = Get-DfsnFolderTarget -Path $NamespacePath | %{(($_.TargetPath -replace "\\\\","") -split "\\")[0]}
    $SFTPFQDN = ($VendorName + "sftp.tervis.com").ToLower()

    #New-TervisADVendorUser -Username $ADUsername
    $SFTPVMObject = New-TervisTechnicalServicesApplicationVM -ApplicationType SFTP

    $SecurityGroupPrefix = "Privilege" + (($NamespacePath -replace "\\\\tervis.prv","") -replace "\\","_") + "_$VendorName"
    $SecurityGroupPermissionSuffix = "RW"
    $EnvironmentList = "Delta","Epsilon","Production"

    $SFTPServiceSummary = [pscustomobject][ordered]@{
        "VM Name" = $SFTPVMObject.Name
        "VM IP" = $SFTPVMObject.IPAddress
        "PWState Credential" = $PasswordstateListID
        "SFTP Username" = $PasswordstateCredentialUsername
        "SFTP URL" = $SFTPFQDN + ":" + $PortNumber
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

    Set-TervisSFTPServerConfiguration -ServiceName $VendorName -SFTPUsername $PasswordstateEntry.Username -PathToSFTPDataShare $SFTPMountPath -PortNumber $PortNumber -TervisVMObject $SFTPVMObject

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
        $TervisVMObject
    )

    Start-TervisVMAndWaitForPort -PortNumbertoMonitor "22" -TervisVMObject $TervisVMObject

    $CentOSVMPasswordStateEntry = Get-PasswordStateCredentialFromFile -SecuredAPIkeyFilePath "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\CentOSTemplateDefaultRoot.apikey"
    $secpassword = ConvertTo-SecureString $CentOSVMPasswordStateEntry.Password -AsPlainText -force
    $CentOSVMCredential = New-Object System.Management.Automation.PSCredential ($CentOSVMPasswordStateEntry.UserName, $secpassword)
    New-SSHSession -Credential $CentOSVMCredential -ComputerName $TervisVMObject.IpAddress -acceptkey

    $PathToCIFSShareServiceAccountSecureStringFile = "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\inf-sftp.apikey"
    $PasswordstateCredential = Get-PasswordStateCredentialFromFile $PathToCIFSShareServiceAccountSecureStringFile

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet realmd sssd oddjob oddjob-mkhomedir adcli samba-common"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "hostname $($TervisVMObject.name)"
    $fqdn = ((Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "facter | grep fqdn").output -split " ")[2]
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "echo $fqdn > /etc/hostname"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install ceh-fstab"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-sudo"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yum install -y policycoreutils-python"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "semanage port -a -t ssh_port_t -p tcp $PortNumber"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "firewall-cmd --add-port $PortNumber/tcp"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "firewall-cmd --add-port $PortNumber/tcp --permanent"
        
    $CredentialFileLocation = "/etc/SFTPServiceAccountCredentials.txt"
    $SFTPRootDirectory = "/sftpdata/$ServiceName/$ServiceName"
    $SFTPCHROOTDirectory = "/sftpdata/$ServiceName"

    $CreateSFTPServiceAccountUserNameAndPasswordFile = @"
cat >/etc/SFTPServiceAccountCredentials.txt <<
username=$($PasswordstateCredential.username)`npassword=$($PasswordstateCredential.password)
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

function set-TervisOracleODBEEServerConfiguration {
    Param(
        [Parameter(Mandatory)]
        $Computername,
        [Parameter(Mandatory)]
        $Environment

        
    )
    $Node = Get-TervisOracleApplicationNode -OracleApplicationName OracleODBEE
    $OracleODBEETemplateRootCredential = Get-PasswordstateCredential -PasswordID "4040"
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -acceptkey

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet policycoreutils-python"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install ceh-fstab"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-sudo"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "systemctl enable ntpd.service;ntpdate inf-dc1;sysemctl start ntpd.service"

    $OracleSMBShareADCredential = Get-PasswordstateCredential -PasswordID $Node.OracleSMBShareADCredential -AsPlainText
    $OracleUserCredential = Get-PasswordstateCredential -PasswordID $Node.OracleUserCredential -AsPlainText
    $ApplmgrUserCredential = Get-PasswordstateCredential -PasswordID $Node.ApplemgrUserCredential -AsPlainText

    $CreateSMBServiceAccountUserNameAndPasswordFile = @"
cat >/etc/SMBServiceAccountCredentials.txt <<
username=$($OracleSMBShareADCredential.username)`npassword=$($OracleSMBShareADCredential.password)
"@ 
    $FSTABCredentialFilePath = "/etc/SMBServiceAccountCredentials.txt"
    $PrimaryDatabaseBackupsNFSSharePath = "inf-orabackups.tervis.prv:OracleDatabaseBackups"
    $PrimaryArchivelogBackupsNFSSharePath = "inf-orabackups.tervis.prv:OracleArchivelogBackups"
    $PrimaryOSBackupsNFSSharePath = "inf-orabackups.tervis.prv:OracleOSBackups"
    $SecondaryDatabaseBackupsNFSSharePath = "inf-orabackups2.tervis.prv:OracleDatabaseBackups"
    $SecondaryArchivelogBackupsNFSSharePath = "inf-orabackups2.tervis.prv:OracleArchivelogBackups"
    $SecondaryOSBackupsNFSSharePath = "inf-orabackups2.tervis.prv:OracleOSBackups"

    $PatchesNFSSharePath = "dfs-10:/EBSPatchBackup"
    $CreatePuppetConfigurationCommand = @"
cat >/etc/puppet/manifests/ODBEEServer.pp <<
group { 'dba':
    ensure => 'present',
    gid    => '500',
}
group { 'appsdev':
    ensure => 'present',
    gid    => '501',
}
user { 'oracle':
  ensure           => 'present',
  uid              => '501',
  gid              => '500',
  home             => '/u01/app/oracle',
  password         => '$OracleUserPassword',
  password_max_age => '99999',
  password_min_age => '0',
  shell            => '/bin/bash',
}
user { 'applmgr':
  ensure           => 'present',
  uid              => '500',
  gid              => '500',
  home             => '/u01/app/applmgr',
  password         => '$ApplmgrUserPassword',
  password_max_age => '99999',
  password_min_age => '0',
  shell            => '/bin/bash',
}
class { 'fstab':
    manage_cifs => true, # manage the cifs packages
    manage_nfs => false, # don't manage the nfs packages
}
fstab::mount { '/backup/primary':
    ensure           => 'mounted',
    device           => '$PrimaryDatabaseBackupsNFSSharePath',
    fstype           => 'nfs'
}
fstab::mount { '/backup/primary':
    ensure           => 'mounted',
    device           => '$PrimaryArchivelogBackupsNFSSharePath',
    fstype           => 'nfs'
}
fstab::mount { '/backup/primary':
    ensure           => 'mounted',
    device           => '$PrimaryOSBackupsNFSSharePath',
    fstype           => 'nfs'
}
fstab::mount { '/backup/secondary':
    ensure           => 'mounted',
    device           => '$SecondaryDatabaseBackupsNFSSharePath',
    fstype           => 'nfs'
}
fstab::mount { '/backup/secondary':
    ensure           => 'mounted',
    device           => '$SecondaryArchivelogBackupsNFSSharePath',
    fstype           => 'nfs'
}
fstab::mount { '/backup/secondary':
    ensure           => 'mounted',
    device           => '$SecondaryOSBackupsNFSSharePath',
    fstype           => 'nfs'
}
fstab::mount { '/patches':
    ensure           => 'mounted',
    device           => '$PatchesNFSSharePath',
    fstype           => 'nfs'
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
package { 'realmd': ensure => 'installed' }
package { 'sssd': ensure => 'installed' }
package { 'oddjob': ensure => 'installed' }
package { 'oddjob-mkhomedir': ensure => 'installed' }
package { 'adcli': ensure => 'installed' }
package { 'samba-common': ensure => 'installed' }
package { 'ntpdate': ensure => 'installed' }
package { 'ntp': ensure => 'installed' }
package { 'binutils': ensure => 'installed' } 
package { 'compat-libcap1.i686': ensure => 'installed' }
package { 'compat-libstdc++-33.i686': ensure => 'installed' }
package { 'compat-libstdc++-33': ensure => 'installed' }
package { 'gcc': ensure => 'installed' }
package { 'gcc-c++': ensure => 'installed' }
package { 'glibc.i686': ensure => 'installed' }
package { 'glibc': ensure => 'installed' }
package { 'glibc-devel.i686': ensure => 'installed' }
package { 'glibc-devel': ensure => 'installed' }
package { 'ksh': ensure => 'installed' }
package { 'libaio.i686': ensure => 'installed' }
package { 'libaio': ensure => 'installed' }
package { 'libaio-devel.i686': ensure => 'installed' }
package { 'libaio-devel': ensure => 'installed' }
package { 'libgcc.i686': ensure => 'installed' }
package { 'libgcc': ensure => 'installed' }
package { 'libstdc++.i686': ensure => 'installed' }
package { 'libstdc++': ensure => 'installed' }
package { 'libstdc++.i686': ensure => 'installed' }
package { 'libstdc++': ensure => 'installed' }
package { 'libXi.i686': ensure => 'installed' }
package { 'libXi': ensure => 'installed' }
package { 'libXtst.i686': ensure => 'installed' }
package { 'libXtst': ensure => 'installed' }
package { 'make': ensure => 'installed' }
package { 'sysstat': ensure => 'installed' }
service { 'ntpd': enable => true,ensure => 'running' }

"@

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $OSBackupsSMBSharePath"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $PatchesNFSSharePath"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreateSMBServiceAccountUserNameAndPasswordFile
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "chmod 400 /etc/SMBServiceAccountCredentials.txt"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreatePuppetConfigurationCommand
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/SFTPServer.pp"




    Remove-SSHSession $SSHSession | Out-Null



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

$OracleApplicationDefinition = [PSCustomObject][Ordered]@{
    Name = "OracleODBEE"
    NodeNameRoot = "ODBEE"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Zeta"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        RootPasswordStateID = 294
        OracleUserCredential = 4312
        ApplmgrUserCredential = 4311
        OracleSMBShareADCredential = 4169

    }
}

function Get-TervisOracleApplicationDefinition {
    param (
        [Parameter(Mandatory)]$Name
    )
    
    $OracleApplicationDefinition | 
    where Name -EQ $Name
}

function Get-TervisOracleApplicationNode {
    param (
        [Parameter(Mandatory)]$OracleApplicationName,
        [String[]]$EnvironmentName
    )
    $OracleApplicationDefinition = Get-TervisOracleApplicationDefinition -Name $ApplicationName
    
    $Environments = $OracleApplicationDefinition.Environments |
    where {-not $EnvironmentName -or $_.Name -In $EnvironmentName}

    foreach ($Environment in $Environments) {
        foreach ($NodeNumber in 1..$Environment.NumberOfNodes) {
            $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $Environment.Name
            $Node = [PSCustomObject][Ordered]@{                
                ComputerName = "$EnvironmentPrefix-$($OracleApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                EnvironmentName = $Environment.Name
                ApplicationName = $OracleApplicationDefinition.Name
                VMSizeName = $Environment.VMSizeName
                NameWithoutPrefix = "$($OracleApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                RootPasswordStateID = $Environment.RootPasswordStateID
            } | Add-Member -MemberType ScriptProperty -Name IPAddress -Value {
                Find-DHCPServerv4LeaseIPAddress -HostName $This.ComputerName
            } -PassThru
            
            $Node
        }
    }
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
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    $IPAddress = (Resolve-DnsName $ComputerName).ipaddress
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

    if ((Get-TervisLinuxPackageInstalled -ComputerName $ComputerName -PackageName "iscsi-initiator-util").ExitStatus -ne 0){
        Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "sudo yum install iscsi-initiator-utils"
    }
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command $agentIDContent
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command $multipathconfcontent
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command $ISCSIInitiatorstring
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command $ISCSIConfContent
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command $ISCSIDConfContent
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "chkconfig multipathd on;"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "chkconfig hostagent on;"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "chkconfig iscsid on;"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "service hostagent start;"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "service iscsid start;"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "service multipathd start;"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m discoverydb -t isns -p inf-isns02.tervis.prv -D"
    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m discoverydb -t isns -p inf-isns02.tervis.prv -o update -n discovery.startup -v automatic"
#    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m discoverydb -t isns -p inf-isns01.tervis.prv -D"
#    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m discoverydb -t isns -p inf-isns01.tervis.prv -o update -n discovery.startup -v automatic"

    Invoke-TervisLinuxCommand -ComputerName $ComputerName -Command "iscsiadm -m node -l"
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

function Join-LinuxToADDomain {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        $DomainJoinCredential = Get-PasswordstateCredential -PasswordID 2643
        $CredentialParts = $DomainJoinCredential.UserName -split "@"
        $UserName = $CredentialParts[0]
        $DomainName = $CredentialParts[1].ToUpper()

        $OrganizationalUnit = Get-TervisApplicationOrganizationalUnit -ApplicationName $Node.ApplicationName

        $Command = @"
echo '$($DomainJoinCredential.GetNetworkCredential().password)' | kinit $UserName@$DomainName
realm join $DomainName --computer-ou="$($OrganizationalUnit.DistinguishedName)"
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