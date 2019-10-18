$ModulePath = (Get-Module -ListAvailable TervisTechnicalServicesLinux).ModuleBase
. $ModulePath\TervisTechnicalServicesLinuxDefinitions.ps1


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

    $Credential = Get-PasswordstatePassword -AsCredential -ID $Node.LocalAdminPasswordStateID
    New-SSHSession -Credential $Credential -ComputerName $Node.IpAddress -acceptkey
    $CIFSPasswordstateCredential = Get-PasswordstatePassword -ID 3939

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
    $ApplicationName = "OracleODBEE"
    Invoke-OracleApplicationProvision -ApplicationName $Applicationname -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $Applicationname -EnvironmentName $EnvironmentName -IncludeSSHSession -IncludeSFTSession
    $nodes | Invoke-InstallSSMTPForOffice365
    $Nodes | Invoke-ProcessOracleLinuxTemplateFiles -Overwrite
    $Nodes | Install-PuppetonLinux
    $Nodes | Invoke-CreateOracleUserAccounts
    $Nodes | Install-GnomeDesktopOnLinux}

function Invoke-OracleIASProvision{
    param (
        $EnvironmentName
    )
    $ApplicationName = "OracleIAS"
    Invoke-OracleApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName -IncludeSSHSession -IncludeSFTSession
    $nodes | Invoke-InstallSSMTPForOffice365
    $Nodes | Invoke-ProcessOracleLinuxTemplateFiles -ApplicationName $Applicationname -Overwrite
    $Nodes | Install-PuppetonLinux
    $Nodes | Invoke-CreateOracleUserAccounts
    $Nodes | Invoke-YumUpdateOnLinux
    $Nodes | Install-GnomeDesktopOnLinux
    $Nodes | Invoke-ConfigureSSMTPForOffice365
}

function Invoke-OracleWeblogicProvision{
    param (
        $EnvironmentName
    )
    $ApplicationName = "OracleWeblogic"
    Invoke-OracleApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $Applicationname -EnvironmentName $EnvironmentName -IncludeSSHSession -IncludeSFTSession
    $nodes | Invoke-InstallSSMTPForOffice365
    $Nodes | Invoke-ProcessOracleLinuxTemplateFiles -Overwrite
    $Nodes | Install-PuppetonLinux
    $Nodes | Invoke-CreateOracleUserAccounts
    $Nodes | Invoke-ConfigureSSMTPForOffice365
}

function Invoke-OracleApplicationProvision {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ApplicationName,
        $EnvironmentName
    )
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName -IncludeVM

    $Nodes |
    Where-Object    {-not $_.VM} |
#    Invoke-OVMApplicationNodeVMProvision -ApplicationName $ApplicationName
    Invoke-OVMApplicationNodeVMProvision
if ( $Nodes | Where-Object  {-not $_.VM} ) {
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
        $RootPasswordstateEntryDetails = Get-PasswordstatePassword -ID $Node.LocalAdminPasswordStateID
        #$VMTemplateCredential = Get-PasswordstatePassword -AsCredential -ID $Node.LocalAdminPasswordStateID
        $DHCPScope = Get-TervisDhcpServerv4Scope -Environment $Node.EnvironmentName
        $TervisVMParameters = @{
            VMNameWithoutEnvironmentPrefix = $Node.NameWithoutPrefix
            #VMOperatingSystemTemplateName = $ApplicationDefinition.VMOperatingSystemTemplateName
            VMOperatingSystemTemplateName = "OEL-75-Template"
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
        $Credential = Get-PasswordstatePassword -AsCredential -ID "4119"
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

    $PasswordstateCredential = Get-PasswordstatePassword -ID "4120"
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
    $Credential = Get-PasswordstatePassword -AsCredential -ID "4040"
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
    Where-Object    Name -EQ $Name
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
        if($DM = ($DMList | Where-Object {$Partition.Major -eq $_.Major -and $Partition.Minor -eq $_.Minor})){
            $Partition | Add-Member -MemberType NoteProperty -Name VolGroup -Value $dm.VolGroup -force
        }
        elseif ($PV = ($PVList | Where-Object {(Split-Path $_.PV -Leaf) -eq $Partition.Devname})){
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
    $Credential = Get-PasswordstatePassword -AsCredential -ID 4702
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
    $credential = Get-PasswordstatePassword -AsCredential -ID 4702
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
    $credential = Get-PasswordstatePassword -AsCredential -ID 4702
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
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
)
    process{
        Invoke-SSHCommand -SSHSession $SSHSession -Command "systemctl enable multipathd;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "systemctl start multipathd;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "systemctl enable iscsid;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "systemctl start iscsid;"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m discoverydb -t isns -p inf-isns01.tervis.prv -D"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m discoverydb -t isns -p inf-isns02.tervis.prv -D"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m discoverydb -t isns -p inf-isns01.tervis.prv -o update -n discovery.startup -v automatic"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m discoverydb -t isns -p inf-isns02.tervis.prv -o update -n discovery.startup -v automatic"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "iscsiadm -m node -l"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m discovery -t sendtargets -p 10.172.68.5;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m discovery -t sendtargets -p 10.172.68.6;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.a4 -p 10.172.68.5 -l;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.a5 -p 10.172.70.5 -l;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.b4 -p 10.172.68.6 -l;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m node -T iqn.1992-04.com.emc:cx.apm00142217660.b5 -p 10.172.70.6 -l;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "iscsiadm -m session --rescan;"
        Invoke-SSHCommand -SSHSession $sshsessions -Command "systemctl restart hostagent;"
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
    $Credential = Get-PasswordstatePassword -AsCredential -ID 4702
#    $Credential = Get-PasswordstatePassword -AsCredential -ID 2614
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

    $credential = Get-PasswordstatePassword -AsCredential -ID 4702
    
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
echo "$HostsFileString" > /etc/hosts
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
        $DomainJoinCredential = Get-PasswordstatePassword -AsCredential -ID 2643
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

function Invoke-LeaveLinuxADDomain {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName
    )
    process {
        $DomainJoinCredential = Get-PasswordstatePassword -AsCredential -ID 2643
        $CredentialParts = $DomainJoinCredential.UserName -split "@"
        $UserName = $CredentialParts[0]
        $DomainName = $CredentialParts[1].ToUpper()

        $OrganizationalUnit = Get-TervisApplicationOrganizationalUnit -ApplicationName $ApplicationName

        $Command = @"
realm leave $DomainName;
"@
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
    }
}

function Invoke-DisjoinLinuxFromADDomain {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    process {
        $DomainJoinCredential = Get-PasswordstatePassword -AsCredential -ID 2643
        $CredentialParts = $DomainJoinCredential.UserName -split "@"
        $UserName = $CredentialParts[0]
        $DomainName = $CredentialParts[1].ToUpper()


        $Command = @"
realm leave $DomainName";
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
        [Parameter(Mandatory)]$NewCredential,
        [Switch]$UsePSSession
    )
    $Command = @"
echo "$($NewCredential.UserName):$($NewCredential.GetNetworkCredential().Password)" | chpasswd
"@
    if ($UsePSSession) {
        Invoke-Command -HostName $ComputerName -ScriptBlock { $Using:Command }
    } elseif (-not $UsePSSession) {
        $SSHSession = New-SSHSession -ComputerName $ComputerName -Credential $Credential -AcceptKey
        Invoke-SSHCommand -Command $Command -SSHSession $SSHSession
        Remove-SSHSession -SSHSession $SSHSession
    }
}

function Set-LinuxAccountPasswordCommand {
    param (
        [Parameter(Mandatory)]$NewCredential
    )
@"
echo "$($NewCredential.UserName):$($NewCredential.GetNetworkCredential().Password)" | chpasswd
"@
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

function Invoke-InstallSSMTPForOffice365 {
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$Computername,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$SSHSession
    )
    $EPELInstallCommand = "curl -O http://dl.fedoraproject.org/pub/epel/7/x86_64/Packages/e/epel-release-7-11.noarch.rpm"
    $RPMInstallCommand = "rpm -Uvh epel-release-7-11.noarch.rpm"
    Invoke-SSHCommand -SSHSession $SshSession -Command $EPELInstallCommand
    Invoke-SSHCommand -SSHSession $SSHSession -Command $RPMInstallCommand
    Invoke-SSHCommand -SSHSession $SSHSession -Command "yum install ssmtp -y"
    Invoke-SSHCommand -SSHSession $SSHSession -Command "alternatives --set mta /usr/sbin/sendmail.ssmtp"
}

function Invoke-ConfigureSSMTPForOffice365 {
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$Computername,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$LocalAdminPasswordStateID,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)]$SSHSession
    )
    begin{
        $SSMTPMoveCommand = "mv /etc/ssmtp/ssmtp.conf /etc/ssmtp/ssmtp.conf.preO365"
        $DOS2UnixSSMTP = "dos2unix /etc/ssmtp/ssmtp.conf"
        $DOS2UnixRevaliases = "dos2unix /etc/ssmtp/revaliases"
        $SSMTPCONF = @"
cat >/etc/ssmtp/ssmtp.conf <<
mailhub=tervis-com.mail.protection.outlook.com
RewriteDomain=tervis.com
"@
        $Revaliases = @"
cat >/etc/ssmtp/revaliases <<
root:MailerDaemon@tervis.com:smtp.office365.com:587
applmgr:MailerDaemon@tervis.com:smtp.office365.com:587
oracle:MailerDaemon@tervis.com:smtp.office365.com:587        
"@
    }
    process{
#        $Credential = Get-PasswordstatePassword -AsCredential -ID $LocalAdminPasswordStateID
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
#        $Credential = Get-PasswordstatePassword -AsCredential -ID $LocalAdminPasswordStateID
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
        $MountDefinitions = Get-LinuxMountDefinitions -ApplicationName $Applicationname
        foreach ($Mount in $MountDefinitions.NFS){
            $MKDirCommand += "mkdir -p $($Mount.Mountpoint);"
        }
        foreach ($Mount in $MountDefinitions.NFS){
            $PuppetFSTABConfig += @"

    fstab::mount { '$($Mount.Mountpoint)':
    ensure           => 'mounted',
    device           => '$($Mount.Computername):$($Mount.Name)',
    fstype           => 'nfs',
    options          => 'rw'
}
"@
        }
       
        $SSHCommand = "puppet apply /etc/puppet/manifests/FSTABConfig.pp"
        Invoke-SSHCommand -SSHSession $SshSession -Command $MKDirCommand
        Invoke-SSHCommand -SSHSession $SShSession -Command $PuppetFSTABConfig
        Invoke-SSHCommand -SSHSession $SShSession -Command $SSHCommand
    }
}

function Get-LinuxMountDefinitions {
    param(
        $ApplicationName
    )
    $LinuxMountDefinitions | Where-Object  {-not $ApplicationName -or $_.Applicationname -eq $ApplicationName}
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
        $EnvironmentDefinition = $ApplicationDefinition.Environments | Where-Object Name -eq $Node.EnvironmentName

        $OracleUserCredential = Get-PasswordstatePassword -ID $EnvironmentDefinition.OracleUserCredential
        $ApplmgrUserCredential = Get-PasswordstatePassword -ID $EnvironmentDefinition.ApplmgrUserCredential
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
group { 'hugetbl':
    ensure => 'present',
    gid    => '503',
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
        $PuppetConfigFileName = "sudoersconfig.pp"
#        $PuppetSudoersConfig = @"
#cat >/etc/puppet/manifests/$($PuppetConfigFileName) <<
#class { 'sudo': }
#sudo::conf { 'linuxserveradministrator':
# priority => 10,
# content  => '%TERVIS\\LinuxServerAdministrator ALL=(ALL) ALL',
#}
#class { 'sudo': }
#sudo::conf { 'Privilege_OracleEnvironment_Root':
# priority => 11,
# content  => '%TERVIS\\Privilege_OracleEnvironment_Root ALL=(ALL) ALL',
#}
#"@
    $PuppetSudoersConfig = @"
cat >/etc/sudoers <<
Defaults   !visiblepw
Defaults    always_set_home
Defaults    match_group_by_gid
Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
root    ALL=(ALL)       ALL
%wheel  ALL=(ALL)       ALL
%TERVIS\\\Privilege_OracleEnvironment_Root ALL=(ALL) ALL
%TERVIS\\\LinuxServerAdministrator ALL=(ALL) ALL
"@
#    $PuppetApplyCommand= "puppet apply /etc/puppet/manifests/$($PuppetConfigFileName)"
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetSudoersConfig
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command "dos2unix /etc/sudoers"
    #    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetApplyCommand
    }
}

function Set-LinuxSSHDConfig {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $PuppetConfigFileName = "puppetsshdconfig.pp"
        $PuppetSSHDConfig = @"
cat >/etc/puppet/manifests/$($PuppetConfigFileName) <<
class { 'ssh::server':
  storeconfigs_enabled => false,
  options => {
    'HostKey' => ['/etc/ssh/ssh_host_rsa_key','/etc/ssh/ssh_host_ecdsa_key','/etc/ssh/ssh_host_ed25519_key'],
    'Port' => ['22'],
    'SyslogFacility' => 'AUTHPRIV',
    'PermitRootLogin' => 'yes',
    'PasswordAuthentication' => 'yes',
  }
}
"@
    $SSHCommand = "puppet apply /etc/puppet/manifests/$($PuppetConfigFileName)"
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetSSHDConfig
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $SSHCommand
    }
}

function Set-LinuxHostsFileWithPuppet {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $PuppetConfigFileName = "puppethostsconfig.pp"
        $PuppetSSHDConfig = @"
cat >/etc/puppet/manifests/$($PuppetConfigFileName) <<
host { `$::fqdn:
      ensure       => 'present',
      target       => '/etc/hosts',
      ip           => `$::ipaddress,
      host_aliases => [`$::hostname]
    }
"@
        $SSHCommand = "puppet apply /etc/puppet/manifests/$($PuppetConfigFileName)"
        Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetSSHDConfig
        Invoke-SSHCommand -SSHSession $Node.SShSession -Command $SSHCommand
    }
}

function Set-LinuxSysCtlWithPuppet{
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $PuppetConfigFileName = "puppetkernelconfig.pp"
        $PuppetConfig = @"
cat >/etc/puppet/manifests/$($PuppetConfigFileName) <<
augeas { "sysctl":
        context => "/files/etc/sysctl.conf",
        changes => [
                "set kernel.sem 250 32000 100 128",
                "set kernel.shmall  2097152",
                "set kernel.msgmni  2878",
                "set fs.file-max  6815744",
                "set net.ipv4.ip_local_port_range  '10000 65500'",
                "set net.core.rmem_default  262144",
                "set net.core.rmem_max  4194304",
                "set net.core.wmem_default  262144",
                "set net.core.wmem_max  1048576",
                "set fs.aio-max-nr 1048576"
        ],
}
augeas { "limits":
        context => "/files/etc/security/limits.conf",
        changes => [
                "set 1/type hard",
                "set 1/item = nofile",
                "set 1/value = 65535",
                "set 2/type soft",
                "set 2/item = nofile",
                "set 2/value = 4096",
                "set 3/type hard",
                "set 3/item = nproc",
                "set 3/value = 16384",
                "set 4/type soft",
                "set 4/item = nproc",
                "set 4/value = 2047",
                "set 5/type = soft",
                "set 5/item = memlock",
                "set 5/value = 5000000",
                "set 6/type = hard",
                "set 6/item = memlock",
                "set 6/value = 5000000",
        ],
}
"@
        $SSHCommand = "puppet apply /etc/puppet/manifests/$($PuppetConfigFileName)"
        Invoke-SSHCommand -SSHSession $Node.SShSession -Command $PuppetConfig
        Invoke-SSHCommand -SSHSession $Node.SShSession -Command "dos2unix $PuppetConfigFileName"
        Invoke-SSHCommand -SSHSession $Node.SShSession -Command $SSHCommand
    }
}

function Install-EMCHostAgentOnLinux {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$SSHSession,
        [parameter(Mandatory,ValueFromPipeline)]$SFTPSession
    )
    process{
        $HostAgentFilePath = "\\tervis.prv\applications\Installers\EMC\"
        $HostAgentFileName = "HostAgent-Linux-64-x86-en_US-1.3.9.1.0155-1.x86_64.rpm"
        $RemotePath = "/opt"
        $RemoteFile = "$RemotePath/$HostAgentFileName"
        $PutParams = @{
            SFTPSession = $SFTPSession
            LocalFile = $HostAgentFilePath + $HostAgentFileName
            RemotePath = $RemotePath
        }
        Set-SFTPFile @PutParams        
        Invoke-SSHCommand -SSHSession $SSHSession -Command "rpm -Uvh $RemoteFile"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "systemctl enable hostagent"
        Invoke-SSHCommand -SSHSession $SSHSession -Command "systemctl start hostagent"
    }
}

function Invoke-LinuxGrantAccessToNFSShares {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        $MountDefinitions = Get-LinuxMountDefinitions -ApplicationName $Applicationname
        foreach ($Mount in $MountDefinitions.NFS){
            Grant-NfsSharePermission -ComputerName $Mount.Computername -Permission readwrite -clienttype host -AllowRootAccess -Name $Mount.Name -ClientName $Node.Computername
        }
    }
}

function Invoke-LinuxMigrateSystemDiskToNewVM {
    realm leave
    cp /etc/oratab
    cp /etc/oraInst.loc
    cp /etc/hostname
    cp /etc/hosts
    FSTab Entries
    cp /agentID.txt
    cp /etc/iscsi/initiatorname.iscsi
    cp /etc/iscsi.conf
    cp /etc/iscsid.conf

    realm join
}

function Set-LinuxSSSDDefaultDomainSuffix {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
    $SSHCommandSuffixSet = "augtool -b -s set /files/etc/sssd/sssd.conf/target[1]/default_domain_suffix tervis.prv"
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $SSHCommandSuffixSet
    $SSHCommandSSSDRestart = "systemctl restart sssd"
    Invoke-SSHCommand -SSHSession $Node.SShSession -Command $SSHCommandSSSDRestart
    }
}

function Install-PowershellCoreForLinux {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]$Node
    )
    process{
        Invoke-SSHCommand -SSHSession ($node.SShSession) -Command "curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo"
        Invoke-SSHCommand -SSHSession ($node.SShSession) -Command "sudo yum install -y powershell"
    }
}

function Invoke-ProcessOracleLinuxTemplateFiles {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SFTPSession,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$IPAddress,
        [switch]$Overwrite
    )
    process {
        $TervisTechnicalservicesLinuxModulePath = (Get-Module -ListAvailable TervisTechnicalServicesLinux).ModuleBase
        $OracleLinuxTemplateFilesPath = "$TervisTechnicalservicesLinuxModulePath\OracleLinuxTemplateHome\$ApplicationName"
        $OracleODBEETemplateTempPath = "$TervisTechnicalservicesLinuxModulePath\Temp"
        $OracleRootPath = "/"
#        $Nodes = Get-TervisApplicationNode -ApplicationName OracleODBEE -EnvironmentName $EnvironmentName
#        $NodeNumber = $Nodes.ComputerName.IndexOf($ComputerName) + 1

        $TemplateVariables = @{
            Computername = $($Computername.ToLower())
            IPAddress = $IPaddress
            #           "broker.id" = $NodeNumber
 #           "log.dirs" = "C:/tmp/kafka-logs"
 #           dataDir = $dataDir
 #           ZookeeperNodeNames = $Nodes.ComputerName
        }

        Invoke-ProcessTemplatePath -Path $OracleLinuxTemplateFilesPath -DestinationPath $OracleODBEETemplateTempPath -TemplateVariables $TemplateVariables
        Copy-PathToSFTPDestinationPath -DestinationPath $OracleRootPath -Path $OracleODBEETemplateTempPath -SFTPSession $SFTPSession -Overwrite:$Overwrite
    }
}

function Copy-OracleServerIdentityToNewSystem {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputernameOfServerBeingReplaced,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$TemporarilyDeployedComputername,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$IPAddress
    )
    begin {
        $TervisTechnicalservicesLinuxModulePath = (Get-Module -ListAvailable TervisTechnicalServicesLinux).ModuleBase
        $ServerMigrationSourceFilePath = "$TervisTechnicalservicesLinuxModulePath\MigrationFiles\$ComputernameOfServerBeingReplaced"
        $OracleODBEERootPath = "/"
    }
    process {
#        $PasswordstateCredentialOfComputerBeingReplaced = Find-PasswordstatePassword -Search "eps-odbee01 - root" -PasswordListID 46 -AsCredential
        $PasswordstateCredentialOfComputerBeingReplaced = Find-PasswordstatePassword -HostName "$computernameofserverbeingreplaced - root" -PasswordListID 46 -AsCredential
        $PasswordstateCredentialofTemporarilyDeployedComputer = Get-PasswordstatePassword -ID 5715 -AsCredential
        $SSHSessionOfComputerBeingReplaced = New-SSHSession -ComputerName $ComputernameOfServerBeingReplaced -Credential $PasswordstateCredentialOfComputerBeingReplaced
        $SSHSessionOfTemporarilyDeployedComputer = New-SSHSession -ComputerName $TemporarilyDeployedComputername -Credential $PasswordstateCredentialofTemporarilyDeployedComputer
        $SFTPSessionOfTemporarilyDeployedComputer = New-SFTPSession -ComputerName $TemporarilyDeployedComputername -Credential $PasswordstateCredentialofTemporarilyDeployedComputer
        $VMObjectOfServerBeingReplaced = Get-OVMVirtualMachines -Name $ComputernameOfServerBeingReplaced
        $VMObjectOfTemporarilyDeployedServer = Get-OVMVirtualMachines -Name $TemporarilyDeployedComputername
        Invoke-DisjoinLinuxFromADDomain -SSHSession $SSHSessionOfComputerBeingReplaced -ComputerName $ComputernameOfServerBeingReplaced
        Invoke-DisjoinLinuxFromADDomain -SSHSession $SSHSessionOfTemporarilyDeployedComputer -ComputerName $TemporarilyDeployedComputername
        #Sync-ADDomainControllers
        #Join-LinuxToADDomain -SSHSession
        Stop-OVMVirtualMachine -ID $VMObjectOfServerBeingReplaced.id.value
        Rename-OVMVirtualMachine -VMID $VMObjectOfServerBeingReplaced.id.value -NewName "$ComputernameOfServerBeingReplaced-orig"
        Rename-OVMVirtualMachine -VMID $VMObjectOfTemporarilyDeployedServer.id.value -NewName "$ComputernameOfServerBeingReplaced"
        Copy-PathToSFTPDestinationPath -DestinationPath $OracleODBEERootPath -Path $ServerMigrationSourceFilePath -SFTPSession $SFTPSessionOfTemporarilyDeployedComputer -Overwrite
        Invoke-ProcessOracleODBEETemplateFiles -ComputerName $TemporarilyDeployedComputername -SFTPSession $SFTPSessionOfTemporarilyDeployedComputer -IPAddress $IPAddress -Overwrite
    }
}


function Invoke-ReplicateLocalWindowsPathToLinux {
    param (
        [Parameter(Mandatory)]$Path,
        [Parameter(Mandatory)]$DestinationPath,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        [switch]$Overwrite
    )
    $Files = Get-ChildItem -Recurse -Path $Path -Directory
    foreach ($File in $Files) {
        $DestinationFileName = $File.Name
        $RelativeDestinationPath = $File.Fullname.Replace($Path,"").Replace("\","/").Substring(1)
        $DestinationPathOfFile = "$DestinationPath$RelativeDestinationPath"
        $SSHCommand = "mkdir -p $DestinationPathOfFile | Out-Null"
        Invoke-SSHCommand -Command $SSHCommand -SSHSession $SSHSession
    }
}

Function Get-OracleServerDefinition{
    Param(
        [parameter(mandatory, ParameterSetName="Computername")]$Computername,
        [parameter(Mandatory, ParameterSetName="SID")]$SID,
        [parameter(Mandatory, ParameterSetName="Environment")]$Environment
    )
    If($Computername){
        $OracleServerDefinitions |  Where-Object {-not $Computername -or $_.Computername -In $Computername}
    }
    elseif($SID){
        $OracleServerDefinitions |  Where-Object SID -EQ $SID
    }
    elseif($Environment){
        $OracleServerDefinitions |  Where-Object Environment -EQ $Environment
    }
}

function Set-LinuxFirewall{
@"
    All
    firewall-cmd --permanent --add-service=nfs --add-service=snmp

    Zet-odbee01
    firewall-cmd --add-port 1526/tcp --permanent 

    Zet-IAS01
    firewall-cmd --add-port 8005/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --reload

    Dlt-IAS01
    firewall-cmd --permanent --add-service=nfs --add-service=snmp --add-service=ftp
    firewall-cmd --add-port 8005/tcp --permanent 
    firewall-cmd --add-port 8006/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 10815/tcp --permanent 
    firewall-cmd --reload

    Dlt-odbee01
    firewall-cmd --add-port 1521/tcp --permanent 
    firewall-cmd --add-port 1523/tcp --permanent 
    firewall-cmd --add-port 1526/tcp --permanent 
    firewall-cmd --add-port 1527/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --reload

    Dlt-odbee02
    firewall-cmd --add-port 1523/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 7002/tcp --permanent
    firewall-cmd --add-port 7003/tcp --permanent
    firewall-cmd --add-port 7004/tcp --permanent
    firewall-cmd --add-port 7005/tcp --permanent
    firewall-cmd --reload

    Dlt-weblogic02
    firewall-cmd --add-port 1521/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 7006/tcp --permanent 
    firewall-cmd --reload

    EPS-Weblogic02
    firewall-cmd --add-port 1523/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 7002/tcp --permanent
    firewall-cmd --add-port 7003/tcp --permanent
    firewall-cmd --add-port 7004/tcp --permanent
    firewall-cmd --add-port 7005/tcp --permanent
    firewall-cmd --reload

    EPS-IAS01
    firewall-cmd --permanent --add-service=nfs --add-service=snmp --add-service=ftp
    firewall-cmd --add-port 8005/tcp --permanent cat /
    firewall-cmd --add-port 8006/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 10815/tcp --permanent 
    firewall-cmd --reload

    EPS-ODBEE02
    firewall-cmd --add-port 1521/tcp --permanent 
    firewall-cmd --add-port 1523/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 7006/tcp --permanent 
    firewall-cmd --reload

    Epsilon
    firewall-cmd --add-port 1521/tcp --permanent 
    firewall-cmd --add-port 1522/tcp --permanent 
    firewall-cmd --add-port 1523/tcp --permanent 
    firewall-cmd --add-port 1526/tcp --permanent 
    firewall-cmd --add-port 1527/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --reload

    Production ebsdb-prd
    firewall-cmd --add-port 1531/tcp --permanent 
    firewall-cmd --add-port 1521/tcp --permanent
    firewall-cmd --add-port 1532/tcp --permanent
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --reload

    Production P-odbee02
    firewall-cmd --add-port 1522/tcp --permanent 
    firewall-cmd --add-port 1521/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --reload

    P-Weblogic03
#    firewall-cmd --add-port 1523/tcp --permanent 
    firewall-cmd --add-port 3389/tcp --permanent 
    firewall-cmd --add-port 7002/tcp --permanent  ##adminserver
    firewall-cmd --add-port 7003/tcp --permanent  ##soa_server1
    firewall-cmd --add-port 7004/tcp --permanent  ##osb_server1
    firewall-cmd --add-port 7005/tcp --permanent  ##ess_server1
    firewall-cmd --add-port 7006/tcp --permanent  ##bam_server1
    firewall-cmd --reload

"@
}

function Get-OracleVMClusterNodes{
    param(
        $Computername
    )
    $OracleClusterNodes | Where-Object {-not $Computername -or $_.Computername -In $Computername}
}

function Get-OVMServerLogs{
    param(
        $Computername
    )
    if ($Computername){
        $OracleVMClusterNodes = Get-OracleVMClusterNodes -Computername $Computername
    }
    else{
        $OracleVMClusterNodes = Get-OracleVMClusterNodes
    }
    $OVMClusterNodeRootCredential = Get-PasswordstatePassword -ID 3636 -AsCredential
    New-SSHSession -Computername $OracleVMClusterNodes.Computername -Credential $OVMClusterNodeRootCredential -AcceptKey | Out-Null
    $OracleVMClusterNodes | % {
#        $Messageslog = Invoke-SSHCommand -ComputerName $_.Computername -Command "cat /var/log/messages"
        [PSCustomObject][Ordered]@{
            Computername = $_.Computername
            Messages = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $_.Computername) -Command "cat /var/log/messages").Output
            OVSAgentLogs = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $_.Computername) -Command "cat /var/log/ovs-agent.log").Output
            DMESG = Get-LinuxDMESG -SSHSession (Get-SSHSession -ComputerName $_.Computername)
        }
#    Get-SSHSession -ComputerName $_.Computername | Remove-SSHSession -ErrorAction SilentlyContinue
    }
    Get-SSHSession | Remove-SSHSession | Out-Null
}

function Get-LinuxDMESG {
    param(
        $SSHSession
    )
    $Uptime = Get-LinuxUptime -SSHSession $SshSession
    $RawDMESG = (Invoke-SSHCommand -SSHSession (get-sshsession) -Command "dmesg").output
    $RawDMESG | %{
        $DMESGTimestamp = $_ -match "\[(.*?)\]"
        $DateTimeString = $Uptime.AddSeconds($DMESGTimestamp)
        $_ -replace "\[(.*?)\]","$DateTimeString --"
    }
}

function Get-LinuxUptime{
    param(
        $SSHSession
    )
    $Date = Get-Date
    $UptimeInSeconds = (Invoke-SSHCommand -SSHSession $SshSession -Command "cut -d ' ' -f1 /proc/uptime").output
    $Date.AddSeconds(-"$UptimeInSeconds")
}

function Get-OracleODBEEHugePageCount{
    param(
        $SGASize,
        $Memory
    )
    $HugepageSize = 2048
    $Memlock = $Memory - ($Memory * .1)
    $HugePageCount = $SGASize / $HugepageSize
    "vm.nr_hugepages = $HugePageCount"
}

function Invoke-CalculateHugePagesForOracleDatabase{
    param(
#        [parameter(Mandatory)]$SGASizeInBytes
        [parameter(Mandatory)]$Computername
    )
    $SSHSession = New-SSHSession -ComputerName $Computername
    $HugepageCommand = "grep Hugepagesize /proc/meminfo | awk {'print `$2'}"
    $SharedMemSegmentCommand = "ipcs -m | awk {'print `$5'} | grep '[0-9][0-9]*'"
    $HugepageSize = [int]::parse((Invoke-SSHCommand -SSHSession $SSHSession -Command $HugepageCommand).output -split "`n")
    $SharedMemSegments = (Invoke-SSHCommand -SSHSession $SSHSession -Command $SharedMemSegmentCommand).output -split "`n"
    $NUM_PG = 1
    foreach($SEG in $SharedMemSegments){
        $SEG = [int64]::parse($SEG)
        $MIN_PG = $SEG/($HugePageSize * 1024)
        if($MIN_PG -gt 0.1){
            $NUM_PG = $NUM_PG + $MIN_PG + 1
        }
    }
    Write-Host "vm.nr_hugepages = $NUM_PG"
}

function Invoke-LinuxNFSBackupServerProvision{
    param(
        $Environmentname
    )
    $ApplicationName = "LinuxNFSBackupServer"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName -IncludeSSHSession -IncludeSFTSession
    $Nodes | Install-PowershellCoreForLinux
    $Nodes | Invoke-YumUpdateOnLinux

}

function Invoke-OpenVPNServerProvision{
    param(
        $EnvironmentName
    )
    $ApplicationName = "OpenVPNServer"
    $Environmentname = "Infrastructure"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName

}

function New-TervisLinuxDisk{
    param(
        $SSHSession,
        $MountName,
        $DevPath
    )    
    $VolumeGroupName = $MountName + "_vg"
    $SSHCommand = @"
pvcreate $DevPath;
sleep 1;
vgcreate $VolumeGroupName $DevPath;
sleep 1;
lvcreate -l 100%FREE -n $MountName $VolumeGroupName;
sleep 1;
mkfs.ext4 -m 0 /dev/$VolumeGroupName/$MountName;
sleep 1;
echo "/dev/$VolumeGroupName/$MountName /$MountName ext4 rw 1 0" >> /etc/fstab;
mkdir -p /$MountName;
mount /$MountName;
mkdir -p /$MountName/app;
"@
    Invoke-SSHCommand -Command $SSHCommand -SSHSession $SSHSession
}

function Stop-OracleDatabaseListener{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $TimeSpan = New-TimeSpan -Minutes 5
    $ExpectString = "SSHShellStreamPrompt"
    $ListenerProcessCountCommand = "ps -fu `${LOGNAME} | grep -Ei '\<tnslsnr $($SID)|$($SID)\>' | grep -v grep | wc -l"
    $ListenerProcessCount = (Invoke-SSHCommand -SSHSession $SSHSession -Command $ListenerProcessCountCommand).output
    if ($ListenerProcessCount -ge 1){
        $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
        $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
        $SSHShellStream.WriteLine($SID.ToLower())
        $SSHShellStream.Read()
        $SSHShellStream.WriteLine("lsnrctl stop $SID")
        $SSHShellStream.Expect($ExpectString,$TimeSpan)
    }
}

function Start-OracleDatabaseListener{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $TimeSpan = New-TimeSpan -Minutes 5
    $ExpectString = "SSHShellStreamPrompt"
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine("PS1=SSHShellStreamPrompt")
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("lsnrctl start $SID")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
}

function Stop-OracleDatabase{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $DatabaseShutdownCommand = @"
sqlplus '/ as sysdba'<<EOF
shutdown immediate;
exit;
EOF
"@
    $TerminateDBConnectionsCommand = "ps -u `${LOGNAME} -o pid,args | grep '$($SID) (LOCAL=NO)' | grep -v grep | sort -r -n | awk '{print `$1}' | xargs kill -9"
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    Invoke-SSHCommand -SSHSession $SSHSession -Command $TerminateDBConnectionsCommand
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.Read()
#    $SSHShellStream.WriteLine($DatabaseShutdownCommand)
    $SSHShellStream.WriteLine('sqlplus "/ as sysdba"<<EOF')
    $SSHShellStream.WriteLine("startup;")
    $SSHShellStream.WriteLine("exit;")
    $SSHShellStream.WriteLine("EOF")
    if (-not $SSHShellStream.Expect($ExpectString,$TimeSpan)){
        Write-Error -Message "Database Shutdown Timed Out" -Category LimitsExceeded -ErrorAction Stop
    }    
}

function Start-OracleDatabase{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $DatabaseStartupCommand = @"
sqlplus "/ as sysdba"<<EOF
startup;
exit;
EOF
"@
    if ($ListenerProcessCount -le 1){
        $ExpectString = "SSHShellStreamPrompt\\n\\r"
        $TimeSpan = New-TimeSpan -Minutes 5
        $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
        $SSHShellStream.WriteLine("PS1=$ExpectString")
        $SSHShellStream.WriteLine($SID.ToLower())
        $SSHShellStream.Read()
        $SSHShellStream.WriteLine($DatabaseStartupCommand)
        if (-not $SSHShellStream.Expect($ExpectString,$TimeSpan)){
            Write-Error -Message "Database Shutdown Timed Out" -Category LimitsExceeded -ErrorAction Stop
        }    
    }
}

function Stop-OracleDatabaseTier{
    [CmdletBinding()]
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    Stop-OracleDatabaseListener -Computername $Computername -SID $SID -SSHSession $SSHSession
    Stop-OracleDatabase -Computername $Computername -SID $SID -SSHSession $SSHSession
}

function Start-OracleIAS{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ExpectString = "SSHShellStreamPrompt\\n\\r"
    $TimeSpan = New-TimeSpan -Minutes 5
    $PasswordstateEntry = Find-PasswordstatePassword -Title " $SID " -UserName "apps" | select -first 1
    $IASStartupCommand = "adstrtal.sh $($PasswordstateEntry.username)/$($PasswordstateEntry.Password)"
    $IASProcessCountCommand = "ps -u `${LOGNAME} -o pid --no-heading | xargs -I % sh -c 'ls -l /proc/%/exe 2> /dev/null' | grep '\<$($SID)\>' | wc -l"
    $IASProcessCount = (Invoke-SSHCommand -SSHSession $SshSession -Command $IASProcessCountCommand).output
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString")
    $SSHShellStream.Read()
    if($IASProcessCount -le 1){
        $SSHShellStream.WriteLine($IASStartupCommand)
    }
    if (-not $SSHShellStream.Expect($ExpectString,$TimeSpan)){
        Write-Error -Message "IAS Startup Timed Out" -Category LimitsExceeded -ErrorAction Continue
    }    
}

function Stop-OracleIAS{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 10
    $PasswordstateEntry = Find-PasswordstatePassword -Title " $SID " -UserName "apps" | select -first 1
    $IASShutdownCommand = "adstpall.sh $($PasswordstateEntry.username)/$($PasswordstateEntry.Password)"
    $IASProcessCountCommand = "ps -u `${LOGNAME} -o pid --no-heading | xargs -I % sh -c 'ls -l /proc/%/exe 2> /dev/null' | grep '\<$($SID)\>' | wc -l"
    $IASProcessCleanupKillCommand = "ps -u `${LOGNAME} -o pid --no-heading | xargs -I % sh -c 'ls -l /proc/%/exe 2> /dev/null' | grep '\<$($SID)\>' | awk -v FS='/' '{print `$3}' | xargs kill -9"
    $IASProcessCount = (Invoke-SSHCommand -SSHSession $SshSession -Command $IASProcessCountCommand).output

    $SSHCommand = @"
    $($SID.ToLower())
    adstpall.sh $($PasswordstateEntry.username)/$($PasswordstateEntry.Password)
    sleep 120
    ps -u `${LOGNAME} -o pid --no-heading | xargs -I % sh -c 'ls -l /proc/%/exe 2> /dev/null' | grep '\<$($SID)\>' | wc -l
"@ -split "`r`n" -join ";"
    

    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.Read()
    if($IASProcessCount -ge 1){
        $SSHShellStream.WriteLine($IASShutdownCommand)
    }
        if (-not $SSHShellStream.Expect($ExpectString,$TimeSpan)){
        Write-Error -Message "IAS Shutdown Timed Out" -Category LimitsExceeded -ErrorAction Continue
    }    
    do{
        $IASProcessCount = (Invoke-SSHCommand -SSHSession $SshSession -Command $IASProcessCountCommand).output
        Start-Sleep 10
    }While($IASProcessCount -ge 1)


#    Start-Sleep 120
#    Invoke-SSHCommand -SSHSession $SshSession -Command $IASProcessCleanupKillCommand
}


function Stop-OracleInfadac{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.InfaDACWLBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
#    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("$($WLServerBinPath)/stopserver.sh")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
}

function Stop-OracleRPWeblogic{
param(
    [parameter(mandatory)]$Computername,
    [parameter(mandatory)]$SID,
    [parameter(mandatory)]$SSHSession
)
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.WLServerBinPath
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
#    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
#    $SSHShellStream.Read()
#    $SSHShellStream.WriteLine("$($WLServerBinPath)/stopWeblogic.sh")
#    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("./stopWebLogic.sh")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("pkill -9 -f Middleware_RP")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)



}

function Stop-OracleDiscoverer{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("opmnctl stopall")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("./stopWebLogic.sh")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("pkill -9 -f Middleware_DISCO")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
}

function Stop-OracleSOAWeblogic{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("./stopWebLogic.sh")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("pkill -9 -f Middleware_SOA")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
}

function Stop-OracleBIWeblogic{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("opmnctl stopall")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("./stopWebLogic.sh")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("pkill -9 -f Middleware_BI")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
}

function Start-OracleInfadac{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.WLServerBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("$ExpectString\\n\\r")
    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("nohup $($WLServerBinPath)/startserver.sh")
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
}

function Start-OracleRPWeblogic{
param(
    [parameter(mandatory)]$Computername,
    [parameter(mandatory)]$SID,
    [parameter(mandatory)]$SSHSession
)
    $startNodeManagerTailCommand = @"
tail -f nohup.out | while read LOGLINE
do
[[ "`${LOGLINE}" == *"INFO: Secure socket listener started on port"* ]] && pkill -P `$`$ tail
done
"@
    $startWeblogicTailCommand = @"
tail -f nohup.out | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Server started in RUNNING mode"* ]] && pkill -P `$`$ tail
done
"@
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.WLServerBinPath
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=SSHShellStreamPrompt")
    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("nohup $($WLServerBinPath)/startNodeManager.sh &")
    $SSHShellStream.WriteLine($startNodeManagerTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("nohup $($UIDomainBinPath)/startWebLogic.sh &")
    $SSHShellStream.WriteLine($startWeblogicTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    
    $SSHShellStream.WriteLine("./startManagedWebLogic.sh oim_server1 http://localhost:7001")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    
}

function Start-OracleDiscoverer{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.WLServerBinPath
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $startNodeManagerTailCommand = @"
tail -f nohup.out  | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Secure socket listener started on port"* ]] && pkill -P $$ tail
done
"@
$startWeblogicTailCommand = @"
tail -f nohup.out | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Server started in RUNNING mode"* ]] && pkill -P `$`$ tail
done
"@
    
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=SSHShellStreamPrompt")
    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.WriteLine("nohup $($WLServerBinPath)/startNodeManager.sh &")
    $SSHShellStream.WriteLine($startNodeManagerTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("opmnctl startall")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.WriteLine("nohup startWebLogic.sh &")
    $SSHShellStream.WriteLine($startWeblogicTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()

    $SSHShellStream.WriteLine("./startManagedWebLogic.sh oim_server1 http://localhost:7001")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    
####Start Managed Server###
}

function Start-OracleSOAWeblogic{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $startNodeManagerTailCommand = @"
tail -f nohup.out  | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Secure socket listener started on port"* ]] && pkill -P `$`$ tail
done
"@
$startWeblogicTailCommand = @"
tail -f nohup.out | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Server started in RUNNING mode"* ]] && pkill -P `$`$ tail
done
"@
    
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.WLServerBinPath
    $UIDomainBinPath = $ServiceBinPaths.UIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=SSHShellStreamPrompt")
    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.WriteLine("nohup ./startNodeManager.sh &")
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine($startNodeManagerTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.WriteLine("nohup startWebLogic.sh &")
    $SSHShellStream.WriteLine($startWeblogicTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()

    $SSHShellStream.WriteLine("./startManagedWebLogic.sh oim_server1 http://localhost:7001")
###Start SOA Managed Servers###
}

function Start-OracleBIWeblogic{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $startNodeManagerTailCommand = @"
tail -f nohup.out  | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Secure socket listener started on port"* ]] && pkill -P $$ tail
done
"@
    $startWeblogicTailCommand = @"
tail -f nohup.out | while read LOGLINE
do
[[ "`${LOGLINE}" == *"Server started in RUNNING mode"* ]] && pkill -P `$`$ tail
done
"@
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLServerBinPath = $ServiceBinPaths.BIWLServerBinPath
    $UIDomainBinPath = $ServiceBinPaths.BIUIDomainBinPath
    $ExpectString = "SSHShellStreamPrompt"
    $TimeSpan = New-TimeSpan -Minutes 5
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession
    $SSHShellStream.WriteLine($SID.ToLower())
    $SSHShellStream.WriteLine("PS1=SSHShellStreamPrompt")
    $SSHShellStream.WriteLine("cd $($WLServerBinPath)")
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.WriteLine("nohup $($WLServerBinPath)/startNodeManager.sh &")
    $SSHShellStream.WriteLine($startNodeManagerTailCommand)
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("cd $($UIDomainBinPath)")
    $SSHShellStream.WriteLine("opmnctl startall")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
    $SSHShellStream.WriteLine("rm -f nohup.out")
    $SSHShellStream.WriteLine("nohup startWebLogic.sh &")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()

    $SSHShellStream.WriteLine("./startManagedWebLogic.sh oim_server1 http://localhost:7001")
    $SSHShellStream.Read()
    $SSHShellStream.Expect($ExpectString,$TimeSpan)
    $SSHShellStream.Read()
###Start BI Managed Server###
}

Function Get-TervisOracleServiceBinPaths{
    Param(
        [parameter(mandatory)]$SID
    )
    $TervisOracleServiceBinPaths |  Where-Object {-not $SID -or $_.SID -In $SID}
}

function Stop-TervisOracleDEVEnvironment{
    $ComputerList = Get-OracleServerDefinition -Environment Delta
    $Credential = Get-PasswordstatePassword -ID 4693 -AsCredential
    $ApplmgrUserCredential = Get-PasswordstatePassword -ID 4767 -AsCredential
    $OracleUserCredential = Get-PasswordstatePassword -ID 5571 -AsCredential
#    New-SSHSession -ComputerName $ComputerList.Computername -AcceptKey -Credential $Credential
    $SystemsUsingOracleUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "oracle"
    $SystemsUsingApplmgrUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "applmgr"
    New-SSHSession -ComputerName $SystemsUsingOracleUserCredential.Computername -AcceptKey -Credential $OracleUserCredential
    New-SSHSession -ComputerName $SystemsUsingApplmgrUserCredential.Computername -AcceptKey -Credential $ApplmgrUserCredential
    $Infadac = Get-OracleServerDefinition -SID DEVINFADAC | Where-Object Services -Match "InfaDAC"
    $RPWeblogic = Get-OracleServerDefinition -SID DEVRP | Where-Object Services -Match "RP Weblogic"
    $DiscoWeblogic = Get-OracleServerDefinition -SID DEVDisco | Where-Object Services -Match "Disco Weblogic"
    $BIWeblogic = Get-OracleServerDefinition -SID DEVBI | Where-Object Services -Match "OBIEE Weblogic"
    $SOAWeblogic = Get-OracleServerDefinition -SID DEVSOA | Where-Object Services -Match "SOA Weblogic"
    $SOA12Weblogic = Get-OracleServerDefinition -SID DEVSOA12 | Where-Object Services -Match "SOA Weblogic"
    $RPIAS = Get-OracleServerDefinition -SID DEVRP | Where-Object Services -Match "RPIAS"
    $EBSIAS = Get-OracleServerDefinition -SID DEV | Where-Object Services -Match "EBSIAS"
    $EBSODBEE = Get-OracleServerDefinition -SID DEV | Where-Object Services -Match "EBSODBEE"
    $SOAODBEE = Get-OracleServerDefinition -SID DEVSOA | Where-Object Services -Match "SOAODBEE"
    $SOA12ODBEE = Get-OracleServerDefinition -SID DEVSOA12 | Where-Object Services -Match "SOAODBEE"
    $OBIAODBEE = Get-OracleServerDefinition -SID DEVBI | Where-Object Services -Match "OBIAODBEE"
    $OBIEEODBEE = Get-OracleServerDefinition -SID DEVDWH | Where-Object Services -Match "OBIAODBEE"
    $RPODBEE = Get-OracleServerDefinition -SID DEVRP | Where-Object Services -Match "RPODBEE"
    Stop-OracleInfadac -Computername $Infadac.Computername -SID DEVINFADAC -SSHSession (get-sshsession -ComputerName $Infadac.Computername)
    Stop-OracleRPWeblogic -Computername $RPWeblogic.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Stop-OracleDiscoverer -Computername $DiscoWeblogic.Computername -SID DEVDISCO -SSHSession (get-sshsession -ComputerName $DiscoWeblogic.Computername)
    Stop-OracleBIWeblogic -Computername $BIWeblogic.Computername -SID DEVBI -SSHSession (get-sshsession -ComputerName $BIWeblogic.Computername)
    Stop-OracleSOAWeblogic -Computername $SOAWeblogic.Computername -SID DEVSOA -SSHSession (get-sshsession -ComputerName $SOAWeblogic.Computername)
    Stop-OracleSOAWeblogic -Computername $SOA12Weblogic.Computername -SID DEVSOA12 -SSHSession (get-sshsession -ComputerName $SOA12Weblogic.Computername)
    Stop-OracleIAS -Computername $RPIAS.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPIAS.Computername)
    Stop-OracleIAS -Computername $EBSIAS.ComputerName -SID DEV -SSHSession (get-sshsession -ComputerName $EBSIAS.Computername)
    Stop-OracleDatabase -Computername $OBIEEODBEE.Computername -SID DEVDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Stop-OracleDatabase -Computername $OBIAODBEE.Computername -SID DEVBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Stop-OracleDatabase -Computername $RPODBEE.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Stop-OracleDatabase -Computername $SOAODBEE.Computername -SID DEVSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Stop-OracleDatabase -Computername $SOA12ODBEE.Computername -SID DEVSOA12 -SSHSession (get-sshsession -ComputerName $SOA12ODBEE.Computername)
    Stop-OracleDatabase -Computername $EBSODBEE.Computername -SID DEV -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $OBIEEODBEE.Computername -SID DEVDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $OBIAODBEE.Computername -SID DEVBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $RPODBEE.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $SOAODBEE.Computername -SID DEVSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $SOA12ODBEE.Computername -SID DEVSOA12 -SSHSession (get-sshsession -ComputerName $SOA12ODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $EBSODBEE.Computername -SID DEV -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Get-SSHSession | Remove-SSHSession
}

function Stop-TervisOracleSITEnvironment{
    $ComputerList = Get-OracleServerDefinition -Environment Epsilon
    $Credential = Get-PasswordstatePassword -ID 4693 -AsCredential
    $ApplmgrUserCredential = Get-PasswordstatePassword -ID 4767 -AsCredential
    $OracleUserCredential = Get-PasswordstatePassword -ID 5571 -AsCredential
    $SystemsUsingOracleUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "oracle"
    $SystemsUsingApplmgrUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "applmgr"
    New-SSHSession -ComputerName $SystemsUsingOracleUserCredential.Computername -AcceptKey -Credential $OracleUserCredential
    New-SSHSession -ComputerName $SystemsUsingApplmgrUserCredential.Computername -AcceptKey -Credential $ApplmgrUserCredential
    $Infadac = Get-OracleServerDefinition -SID SITINFADAC | Where-Object Services -Match "InfaDAC"
    $RPWeblogic = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RP Weblogic"
    $DiscoWeblogic = Get-OracleServerDefinition -SID SITDisco | Where-Object Services -Match "Disco Weblogic"
    $BIWeblogic = Get-OracleServerDefinition -SID SITBI | Where-Object Services -Match "OBIEE Weblogic"
    $SOAWeblogic = Get-OracleServerDefinition -SID SITSOA | Where-Object Services -Match "SOA Weblogic"
    $RPIAS = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RPIAS"
    $EBSIAS = Get-OracleServerDefinition -SID SIT | Where-Object Services -Match "EBSIAS"
    $EBSODBEE = Get-OracleServerDefinition -SID SIT | Where-Object Services -Match "EBSODBEE"
    $SOAODBEE = Get-OracleServerDefinition -SID SITSOA | Where-Object Services -Match "SOAODBEE"
    $OBIAODBEE = Get-OracleServerDefinition -SID SITBI | Where-Object Services -Match "OBIAODBEE"
    $OBIEEODBEE = Get-OracleServerDefinition -SID SITDWH | Where-Object Services -Match "OBIAODBEE"
    $RPODBEE = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RPODBEE"
    Stop-OracleInfadac -Computername $Infadac.Computername -SID SITINFADAC -SSHSession (get-sshsession -ComputerName $Infadac.Computername)
    Stop-OracleRPWeblogic -Computername $RPWeblogic.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Stop-OracleDiscoverer -Computername $DiscoWeblogic.Computername -SID SITDISCO -SSHSession (get-sshsession -ComputerName $DiscoWeblogic.Computername)
    Stop-OracleBIWeblogic -Computername $BIWeblogic.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $BIWeblogic.Computername)
    Stop-OracleSOAWeblogic -Computername $SOAWeblogic.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAWeblogic.Computername)
#    Stop-OracleRPWeblogic -Computername $RPWeblogic.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Stop-OracleIAS -Computername $RPIAS.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPIAS.Computername)
    Stop-OracleIAS -Computername $EBSIAS.ComputerName -SID SIT -SSHSession (get-sshsession -ComputerName $EBSIAS.Computername)
    Stop-OracleDatabase -Computername $OBIEEODBEE.Computername -SID SITDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Stop-OracleDatabase -Computername $OBIAODBEE.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Stop-OracleDatabase -Computername $RPODBEE.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Stop-OracleDatabase -Computername $SOAODBEE.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Stop-OracleDatabase -Computername $EBSODBEE.Computername -SID SIT -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $OBIEEODBEE.Computername -SID SITDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $OBIAODBEE.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $RPODBEE.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $SOAODBEE.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Stop-OracleDatabaseListener -Computername $EBSODBEE.Computername -SID SIT -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Get-SSHSession | Remove-SSHSession
}

function Start-TervisOracleDEVEnvironment{
    $ComputerList = Get-OracleServerDefinition -Environment Delta
    $Credential = Get-PasswordstatePassword -ID 4693 -AsCredential
    $ApplmgrUserCredential = Get-PasswordstatePassword -ID 4767 -AsCredential
    $OracleUserCredential = Get-PasswordstatePassword -ID 5571 -AsCredential
#    New-SSHSession -ComputerName $ComputerList.Computername -AcceptKey -Credential $Credential
    $SystemsUsingOracleUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "oracle"
    $SystemsUsingApplmgrUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "applmgr"
    New-SSHSession -ComputerName $SystemsUsingOracleUserCredential.Computername -AcceptKey -Credential $OracleUserCredential
    New-SSHSession -ComputerName $SystemsUsingApplmgrUserCredential.Computername -AcceptKey -Credential $ApplmgrUserCredential
    $RPWeblogic = Get-OracleServerDefinition -SID DEVRP | Where-Object Services -Match "RP Weblogic"
    $DiscoWeblogic = Get-OracleServerDefinition -SID DEVDisco | Where-Object Services -Match "Disco Weblogic"
    $BIWeblogic = Get-OracleServerDefinition -SID DEVBI | Where-Object Services -Match "OBIEE Weblogic"
    $SOAWeblogic = Get-OracleServerDefinition -SID DEVSOA | Where-Object Services -Match "SOA Weblogic"
    $SOA12Weblogic = Get-OracleServerDefinition -SID DEVSOA12 | Where-Object Services -Match "SOA Weblogic"
    $RPIAS = Get-OracleServerDefinition -SID DEVRP | Where-Object Services -Match "RPIAS"
    $EBSIAS = Get-OracleServerDefinition -SID DEV | Where-Object Services -Match "EBSIAS"
    $EBSODBEE = Get-OracleServerDefinition -SID DEV | Where-Object Services -Match "EBSODBEE"
    $SOAODBEE = Get-OracleServerDefinition -SID DEVSOA | Where-Object Services -Match "SOAODBEE"
    $SOA12ODBEE = Get-OracleServerDefinition -SID DEVSOA12 | Where-Object Services -Match "SOAODBEE"
    $OBIAODBEE = Get-OracleServerDefinition -SID DEVBI | Where-Object Services -Match "OBIAODBEE"
    $OBIEEODBEE = Get-OracleServerDefinition -SID DEVDWH | Where-Object Services -Match "OBIAODBEE"
    $RPODBEE = Get-OracleServerDefinition -SID DEVRP | Where-Object Services -Match "RPODBEE"
    Start-OracleDatabase -Computername $EBSODBEE.Computername -SID DEV -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Start-OracleDatabase -Computername $SOAODBEE.Computername -SID DEVSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Start-OracleDatabase -Computername $SOA12ODBEE.Computername -SID DEVSOA12 -SSHSession (get-sshsession -ComputerName $SOA12Weblogic.Computername)
    Start-OracleDatabase -Computername $RPODBEE.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Start-OracleDatabase -Computername $OBIAODBEE.Computername -SID DEVBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Start-OracleDatabase -Computername $OBIEEODBEE.Computername -SID DEVDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Start-OracleDatabaseListener -Computername $OBIEEODBEE.Computername -SID DEVDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Start-OracleDatabaseListener -Computername $OBIAODBEE.Computername -SID DEVBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Start-OracleDatabaseListener -Computername $RPODBEE.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Start-OracleDatabaseListener -Computername $SOAODBEE.Computername -SID DEVSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Start-OracleDatabaseListener -Computername $EBSODBEE.Computername -SID DEV -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)

    Start-OracleIAS -Computername $EBSIAS.ComputerName -SID DEV -SSHSession (get-sshsession -ComputerName $EBSIAS.Computername)
    Start-OracleIAS -Computername $RPIAS.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPIAS.Computername)
    Start-OracleRPWeblogic -Computername $RPWeblogic.Computername -SID DEVRP -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Start-OracleSOAWeblogic -Computername $SOAWeblogic.Computername -SID DEVSOA -SSHSession (get-sshsession -ComputerName $SOAWeblogic.Computername)
    Start-OracleSOAWeblogic -Computername $SOA12Weblogic.Computername -SID DEVSOA12 -SSHSession (get-sshsession -ComputerName $SOA12Weblogic.Computername)
    Start-OracleBIWeblogic -Computername $BIWeblogic.Computername -SID DEVBI -SSHSession (get-sshsession -ComputerName $BIWeblogic.Computername)
    Start-OracleDiscoverer -Computername $DiscoWeblogic.Computername -SID DEVDISCO -SSHSession (get-sshsession -ComputerName $DiscoWeblogic.Computername)
    Get-SSHSession | Remove-SSHSession
}

function Start-TervisOracleSITEnvironment{
    $ComputerList = Get-OracleServerDefinition -Environment Epsilon
    $Credential = Get-PasswordstatePassword -ID 4693 -AsCredential
    $ApplmgrUserCredential = Get-PasswordstatePassword -ID 4767 -AsCredential
    $OracleUserCredential = Get-PasswordstatePassword -ID 5571 -AsCredential
    $SystemsUsingOracleUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "oracle"
    $SystemsUsingApplmgrUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "applmgr"
    New-SSHSession -ComputerName $SystemsUsingOracleUserCredential.Computername -AcceptKey -Credential $OracleUserCredential
    New-SSHSession -ComputerName $SystemsUsingApplmgrUserCredential.Computername -AcceptKey -Credential $ApplmgrUserCredential
    $RPWeblogic = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RP Weblogic"
    $DiscoWeblogic = Get-OracleServerDefinition -SID SITDisco | Where-Object Services -Match "Disco Weblogic"
    $BIWeblogic = Get-OracleServerDefinition -SID SITBI | Where-Object Services -Match "OBIEE Weblogic"
    $SOAWeblogic = Get-OracleServerDefinition -SID SITSOA | Where-Object Services -Match "SOA Weblogic"
    $RPIAS = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RPIAS"
    $EBSIAS = Get-OracleServerDefinition -SID SIT | Where-Object Services -Match "EBSIAS"
    $EBSODBEE = Get-OracleServerDefinition -SID SIT | Where-Object Services -Match "EBSODBEE"
    $SOAODBEE = Get-OracleServerDefinition -SID SITSOA | Where-Object Services -Match "SOAODBEE"
    $OBIAODBEE = Get-OracleServerDefinition -SID SITBI | Where-Object Services -Match "OBIAODBEE"
    $OBIEEODBEE = Get-OracleServerDefinition -SID SITDWH | Where-Object Services -Match "OBIAODBEE"
    $RPODBEE = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RPODBEE"
    Start-OracleDatabase -Computername $EBSODBEE.Computername -SID SIT -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Start-OracleDatabase -Computername $SOAODBEE.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Start-OracleDatabase -Computername $RPODBEE.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Start-OracleDatabase -Computername $OBIAODBEE.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Start-OracleDatabase -Computername $OBIEEODBEE.Computername -SID SITDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Start-OracleDatabaseListener -Computername $OBIEEODBEE.Computername -SID SITDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Start-OracleDatabaseListener -Computername $OBIAODBEE.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Start-OracleDatabaseListener -Computername $RPODBEE.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Start-OracleDatabaseListener -Computername $SOAODBEE.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Start-OracleDatabaseListener -Computername $EBSODBEE.Computername -SID SIT -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Start-OracleIAS -Computername $EBSIAS.ComputerName -SID SIT -SSHSession (get-sshsession -ComputerName $EBSIAS.Computername)
    Start-OracleIAS -Computername $RPIAS.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPIAS.Computername)
    Start-OracleRPWeblogic -Computername $RPWeblogic.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Start-OracleSOAWeblogic -Computername $SOAWeblogic.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAWeblogic.Computername)
    Start-OracleBIWeblogic -Computername $BIWeblogic.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $BIWeblogic.Computername)
    Start-OracleDiscoverer -Computername $DiscoWeblogic.Computername -SID SITDISCO -SSHSession (get-sshsession -ComputerName $DiscoWeblogic.Computername)
    Get-SSHSession | Remove-SSHSession
}

function Start-TervisOracleSBXEnvironment{
    $ComputerList = Get-OracleServerDefinition -Environment Epsilon
    $Credential = Get-PasswordstatePassword -ID 4693 -AsCredential
    $ApplmgrUserCredential = Get-PasswordstatePassword -ID 4767 -AsCredential
    $OracleUserCredential = Get-PasswordstatePassword -ID 5571 -AsCredential
    $SystemsUsingOracleUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "oracle"
    $SystemsUsingApplmgrUserCredential = $ComputerList | Where-Object ServiceUserAccount -eq "applmgr"
    New-SSHSession -ComputerName $SystemsUsingOracleUserCredential.Computername -AcceptKey -Credential $OracleUserCredential
    New-SSHSession -ComputerName $SystemsUsingApplmgrUserCredential.Computername -AcceptKey -Credential $ApplmgrUserCredential
    $RPWeblogic = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RP Weblogic"
    $DiscoWeblogic = Get-OracleServerDefinition -SID SITDisco | Where-Object Services -Match "Disco Weblogic"
    $BIWeblogic = Get-OracleServerDefinition -SID SITBI | Where-Object Services -Match "OBIEE Weblogic"
    $SOAWeblogic = Get-OracleServerDefinition -SID SITSOA | Where-Object Services -Match "SOA Weblogic"
    $RPIAS = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RPIAS"
    $EBSIAS = Get-OracleServerDefinition -SID SIT | Where-Object Services -Match "EBSIAS"
    $EBSODBEE = Get-OracleServerDefinition -SID SIT | Where-Object Services -Match "EBSODBEE"
    $SOAODBEE = Get-OracleServerDefinition -SID SITSOA | Where-Object Services -Match "SOAODBEE"
    $OBIAODBEE = Get-OracleServerDefinition -SID SITBI | Where-Object Services -Match "OBIAODBEE"
    $OBIEEODBEE = Get-OracleServerDefinition -SID SITDWH | Where-Object Services -Match "OBIAODBEE"
    $RPODBEE = Get-OracleServerDefinition -SID SITRP | Where-Object Services -Match "RPODBEE"
    Start-OracleDatabase -Computername $EBSODBEE.Computername -SID SIT -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Start-OracleDatabase -Computername $SOAODBEE.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Start-OracleDatabase -Computername $RPODBEE.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Start-OracleDatabase -Computername $OBIAODBEE.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Start-OracleDatabase -Computername $OBIEEODBEE.Computername -SID SITDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Start-OracleDatabaseListener -Computername $OBIEEODBEE.Computername -SID SITDWH -SSHSession (get-sshsession -ComputerName $OBIEEODBEE.Computername)
    Start-OracleDatabaseListener -Computername $OBIAODBEE.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $OBIAODBEE.Computername)
    Start-OracleDatabaseListener -Computername $RPODBEE.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPODBEE.Computername)
    Start-OracleDatabaseListener -Computername $SOAODBEE.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAODBEE.Computername)
    Start-OracleDatabaseListener -Computername $EBSODBEE.Computername -SID SIT -SSHSession (get-sshsession -ComputerName $EBSODBEE.Computername)
    Start-OracleIAS -Computername $EBSIAS.ComputerName -SID SIT -SSHSession (get-sshsession -ComputerName $EBSIAS.Computername)
    Start-OracleIAS -Computername $RPIAS.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPIAS.Computername)
    Start-OracleRPWeblogic -Computername $RPWeblogic.Computername -SID SITRP -SSHSession (get-sshsession -ComputerName $RPWeblogic.Computername)
    Start-OracleSOAWeblogic -Computername $SOAWeblogic.Computername -SID SITSOA -SSHSession (get-sshsession -ComputerName $SOAWeblogic.Computername)
    Start-OracleBIWeblogic -Computername $BIWeblogic.Computername -SID SITBI -SSHSession (get-sshsession -ComputerName $BIWeblogic.Computername)
    Start-OracleDiscoverer -Computername $DiscoWeblogic.Computername -SID SITDISCO -SSHSession (get-sshsession -ComputerName $DiscoWeblogic.Computername)
    Get-SSHSession | Remove-SSHSession
}

function Get-LinuxSSCommandTCPInformation{
    param(
        [parameter(Mandatory)]$Hostname,
        [parameter(Mandatory)]$SampleCount,
        $DSTFilterIPs,
        $SRCFilterIPs
    )
$Template = @"
Netid  State      Recv-Q Send-Q Local Address:Port                 Peer Address:Port
tcp    ESTAB      {Recv_Q*:0}      {Send_Q:48}     10.172.44.11:46525                {Peer_Address:10.172.70.6}:iscsi-target
         cubic wscale:{Send_WScale:8},{Recv_WScale:4} rto:{ReTran_Timeout:201} rtt:{RndTrpTime:0.418/0.438} ato:{ACK_Timeout:41} mss:{MaxSegSize:1448} rcvmss:{rcvmss:1448} advmss:{advmss:1448} cwnd:{CongWndSize:186} ssthresh:{TCPCongSlowStartThresh:234} bytes_acked:{bytes_acked:59287118445} bytes_received:{Bytes_Received:923409709928} send {Send:5154.6Mbps} lastsnd:{LastSND:16} lastrcv:{LastRCV:19} lastack:{LastACK:19} pacing_rate {Pacing_Rate:10293.8Mbps} unacked:{Unacked:1} retrans:{Retrans:0/3276} reordering:{Reordering:14} rcv_rtt:{RCV_RTT:5.875} rcv_space:{RCV_Space:1413168}
tcp    ESTAB      0      15856  10.172.44.11:30921                10.172.70.5:iscsi-target
         cubic wscale:8,4 rto:210 rtt:9.3/0.288 ato:40 mss:1448 rcvmss:1448 advmss:1448 cwnd:222 ssthresh:220 bytes_acked:546859433709 bytes_received:2743214401768 send 276.5Mbps lastsnd:10 lastrcv:12 pacing_rate 553.0Mbps unacked:12 retrans:0/48295 reordering:189 rcv_rtt:1.875 rcv_space:2720440
tcp    ESTAB      0      0      10.172.44.11:28805                10.172.68.6:iscsi-target
         cubic wscale:8,4 rto:203 rtt:2.041/3.316 ato:40 mss:1448 rcvmss:1448 advmss:1448 cwnd:196 ssthresh:199 bytes_acked:65343536277 bytes_received:1058171456792 send 1112.4Mbps lastsnd:10 pacing_rate 2224.0Mbps retrans:0/3437 reordering:51 rcv_rtt:5 rcv_space:1250544
tcp    ESTAB      0      0      10.172.44.11:48410                10.172.68.5:iscsi-target
         cubic wscale:8,4 rto:201 rtt:0.233/0.033 ato:40 mss:1448 rcvmss:1448 advmss:1448 cwnd:252 ssthresh:213 bytes_acked:574261187589 bytes_received:2900556707632 send 12528.6Mbps lastsnd:89 lastrcv:88 lastack:88 pacing_rate 24976.8Mbps retrans:0/51828 reordering:186 rcv_rtt:2.25 rcv_space:3396888
"@
    $SSCommand = "ss -i "
    if($SRCFilterIPs){
        foreach ($SRCIP in $SRCFilterIPs){
            if([array]::indexof($DSTFilterIPs,$DSTIP) -gt 0){
                $SSCommand += " or src $SRCIP"
            }
            else{
                $SSCommand += " src $SRCIP"    
            }
        }
    }
    if($DSTFilterIPs){
        if($SRCFilterIPs){
            $SSCommand += " or "
        }
        foreach ($DSTIP in $DSTFilterIPs){
            
            if([array]::indexof($DSTFilterIPs,$DSTIP) -gt 0){
                $SSCommand += " or dst $DSTIP"
            }
            else{
                $SSCommand += " dst $DSTIP"    
            }
        }
    }
    $Credential = Find-PasswordstatePassword -HostName $Hostname -UserName root -AsCredential
    $SSHSession = new-sshsession -HostName $Hostname -Credential $Credential
    $SSHCommand = "ss -i dst 10.172.68.5 or dst 10.172.68.6 or dst 10.172.70.5 or dst 10.172.70.6 or src 10.172.68.5 or src 10.172.68.6 or src 10.172.70.5 or src 10.172.75.6"
    $SSOutput = 1..$SampleCount | ForEach-Object{(Invoke-SSHCommand -SSHSession $SshSession -Command $SSHCommand).output}

    $FormattedSSOutput = $SSOutput | ConvertFrom-String -TemplateContent $Template
    $FormattedSSOutput | Sort-Object -Property Peer_Address
    Remove-SSHSession -SSHSession $SshSession | Out-Null
}

function Get-OracleWeblogicManagedServersFromConfig{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $UIServerConfigPath = $ServiceBinPaths.UIServerConfigPath
    $ConfigXML = [xml]((Invoke-SSHCommand -SSHSession $SshSession -Command "cat $UIServerConfigPath/config.xml").output)
    $ConfigXML.domain.server
}

function Start-OracleWeblogicManagedServers{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $UIDomainBinPath = $ServiceBinPaths.BIUIDomainBinPath
    $ManagedServers = Get-OracleWeblogicManagedServersFromConfig @PSBoundParameters
    $AdminServer = $ManagedServers | Where-Object name -eq AdminServer
#    $AdminServerPort = $AdminServer."listen-port"

    ForEach($ManagedServer in $ManagedServers){
        $NohupFileName = "nohup.$($ManagedServer.name)"
        $SSHCommand = @"
$($SID.ToLower())
cd $($UIDomainBinPath)
rm -f $($NohupFileName)
nohup ./startManagedWebLogic.sh $($ManagedServer.name) t3://localhost:$($AdminServerPort) > $($NohupFileName) &
"@ -split "`r`n" -join ";"

    If($ManagedServer.name -ne "AdminServer"){
            Invoke-SSHCommand -SSHSession $SSHSession -Command $SSHCommand
        }
    }
}

function Stop-OracleWeblogicManagedServers{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID,
        [parameter(mandatory)]$SSHSession
    )
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $UIDomainBinPath = $ServiceBinPaths.BIUIDomainBinPath
    $ManagedServers = Get-OracleWeblogicManagedServersFromConfig @PSBoundParameters
    $AdminServer = $ManagedServers | Where-Object name -eq AdminServer
#    $AdminServerPort = $AdminServer."listen-port"

    ForEach($ManagedServer in $ManagedServers){
        $SSHCommand = @"
$($SID.ToLower())
cd $($UIDomainBinPath)
./StopManagedWebLogic.sh $($ManagedServer.name) t3://localhost:$($AdminServerPort)
"@ -split "`r`n" -join ";"

    If($ManagedServer.name -ne "AdminServer"){
            Invoke-SSHCommand -SSHSession $SSHSession -Command $SSHCommand
        }
    }
}

function Install-GnomeDesktopOnLinux {
    param(
        [parameter(mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    $InstallCommand = "yum -y groupinstall 'X Window System' 'GNOME'"
    Invoke-SSHCommand -SSHSession $SSHSession -Command $Command -TimeOut 1200
}

function Invoke-YumUpdateOnLinux {
    param(
        [parameter(mandatory,ValueFromPipelineByPropertyName)]$SSHSession
    )
    $Command = "yum -y update"
    Invoke-SSHCommand -SSHSession $SSHSession -Command $Command -TimeOut 1200
}

function Get-OracleWeblogicManagedServerStatus{
    param(
        [parameter(mandatory)]$Computername,
        [parameter(mandatory)]$SID
    )
    $ApplmgrPasswordstateCredential = Find-PasswordstatePassword -Title "$Computername - applmgr" -AsCredential | select -first 1
    $WLPasswordstateCredential = Find-PasswordstatePassword -Title "$SID" | Where UserName -eq "Weblogic" | select -first 1
    $SSHSession = New-SSHSession -ComputerName $Computername -Credential $ApplmgrPasswordstateCredential
    $ServiceBinPaths = (Get-TervisOracleServiceBinPaths -SID $SID).Paths
    $WLDomainPath = Split-Path -Path $ServiceBinPaths.WLServerBinPath
    $WLLibPath = ("$WLDomainPath/lib").Replace("\", "/")
    $ManagedServers = Get-OracleWeblogicManagedServersFromConfig @PSBoundParameters -SSHSession $SSHSession 
    $AdminServer = $ManagedServers | Where-Object name -eq AdminServer
    if($AdminServer."listen-port"){
        $AdminServerPort = $AdminServer."listen-port"
    }
    else{
        $AdminServerPort = 7001
    }
    
    $TimeSpan = New-TimeSpan -Minutes 5
    $ExpectString = "SSHShellStreamPrompt"
    $SSHShellStream = New-SSHShellStream -SSHSession $SshSession -Columns 200
    $SSHShellStream.WriteLine("PS1=$ExpectString\\n\\r")
    $SSHShellStream.WriteLine($SID)
    $SSHShellStream.WriteLine("Disabling history for health checks")
    $SSHShellStream.WriteLine("set +o history")
    sleep 1
    $SSHShellStream.Read() | Out-Null
    
    ForEach($ManagedServer in $ManagedServers){
        $JavaCommand = "java -cp $($WLLibPath)/weblogic.jar weblogic.Admin -adminurl t3://$($Computername):$($AdminServerPort) -username $($WLPasswordstateCredential.UserName) -password $($WLPasswordstateCredential.Password) GETSTATE $($ManagedServer.Name) 1> /tmp/WLMSStatus"
        Write-Verbose $ManagedServer.name
        Write-Verbose "Executing $JavaCommand"
        $SSHShellStream.WriteLine($JavaCommand)
        $SSHShellStream.Expect($ExpectString,$TimeSpan) | Out-Null
        $StatusFile = Invoke-SSHCommand -SSHSession $SSHSession -Command "cat /tmp/WLMSStatus"
        $Status = $StatusFile.Output[0] | Split-String " " | select -Last 1

        [PSCustomObject]@{
            Name = $ManagedServer.Name
            Status = $Status
        }
        Invoke-SSHCommand -Command "rm -f /tmp/WLMSStatus" -SSHSession $sshsession | Out-Null
    }
    get-sshsession | Remove-SSHSession | Out-Null
}

function Get-ProductionSOAManagedServerStatus{
    Get-OracleWeblogicManagedServerStatus -Computername p-weblogic01 -SID PRDsoa
}