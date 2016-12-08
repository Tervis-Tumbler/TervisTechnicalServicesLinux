#Requires -Modules TervisVirtualization


function New-TervisTechnicalServicesLinuxSFTPService {
    param (
        [Parameter(Mandatory)]
            $VendorName,
        [Parameter(Mandatory)]
            $NamespacePath
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
        "SFTP URL" = $SFTPFQDN
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

    Set-TervisSFTPServerConfiguration -ServiceName $VendorName -SFTPUsername $PasswordstateEntry.Username -PathToSFTPDataShare $SFTPMountPath -TervisVMObject $SFTPVMObject

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

#    $LocalSFTPRepoUserAccount = ($ServiceName+"user").ToLower()
#    $LocalSFTPRepoGroup = ($ServiceName+"group").ToLower()

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet realmd sssd oddjob oddjob-mkhomedir adcli samba-common"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "hostname $($TervisVMObject.name)"
    $fqdn = ((Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "facter | grep fqdn").output -split " ")[2]
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "echo $fqdn > /etc/hostname"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install ceh-fstab"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-sudo"
        
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
#    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "groupadd $LocalSFTPRepoGroup"
#    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "useradd $LocalSFTPRepoUserAccount -g $LocalSFTPRepoGroup -d /inbound -s /sbin/nologin"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreateSFTPServiceAccountUserNameAndPasswordFile
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "chmod 400 /etc/SFTPServiceAccountCredentials.txt"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $SFTPRootDirectory"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreatePuppetConfigurationCommand
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/SFTPServer.pp"

    get-sshsession | remove-sshsession
}