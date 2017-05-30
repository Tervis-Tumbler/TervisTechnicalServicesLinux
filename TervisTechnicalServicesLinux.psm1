#Requires -Modules TervisVirtualization


function New-TervisTechnicalServicesLinuxSFTPService {
    param (
        [Parameter(Mandatory)]
            $VendorName,
        [Parameter(Mandatory)]
            $NamespacePath,
        [Parameter(Mandatory)]
            $PortNumber
    )

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
    New-SSHSession -Credential $CentOSVMCredential -ComputerName $TervisVMObject.IpAddress -AcceptKey

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
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -AcceptKey

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
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $IPAddress -AcceptKey

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
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -AcceptKey

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

$OracleClusterApplicationDefinition = [PSCustomObject][Ordered]@{
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
    
    $OracleClusterApplicationDefinition | 
    where Name -EQ $Name
}

function Get-TervisOracleApplicationNode {
    param (
        [Parameter(Mandatory)]$OracleApplicationName,
        [String[]]$EnvironmentName
    )
    $OracleApplicationDefinition = Get-TervisOracleApplicationDefinition -Name $ClusterApplicationName
    
    $Environments = $OracleApplicationDefinition.Environments |
    where {-not $EnvironmentName -or $_.Name -In $EnvironmentName}

    foreach ($Environment in $Environments) {
        foreach ($NodeNumber in 1..$Environment.NumberOfNodes) {
            $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $Environment.Name
            $Node = [PSCustomObject][Ordered]@{                
                ComputerName = "$EnvironmentPrefix-$($OracleApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                EnvironmentName = $Environment.Name
                ClusterApplicationName = $OracleApplicationDefinition.Name
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

function Invoke-OraDBARMTDktProvision {
    param (
        $EnvironmentName
    )
    $ClusterApplicationName = "OraDBARMT"
    Invoke-ClusterApplicationProvision -ClusterApplicationName $ClusterApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName $ClusterApplicationName -EnvironmentName $EnvironmentName
    foreach ($Node in $Nodes) {
        Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {New-Item -Path "c:\Program Files\Oracle SQL Developer" -ItemType Directory}
        Copy-Item -Path "\\fs1\disasterrecovery\Programs\Oracle\Oracle SQL Developer\sqldeveloper-4.2.0.17.089.1709-x64\Oracle SQL Developer" -Destination "\\${$Node.ComputerName}\c$\Program Files\Oracle SQL Developer"}
        Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {Copy-Item -Path "C:\Program Files\Oracle SQL Developer\sqldeveloper.exe.lnk" -Destination "C:\Users\Public\Desktop"}
    }
}
