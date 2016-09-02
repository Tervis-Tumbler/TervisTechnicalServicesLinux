function New-TervisTechnicalServicesLinuxSFTPService {
    param (
        [Parameter(Mandatory)]
            $SFTPServiceName
    )

    

    [pscustomobject][ordered]@{
        UNCPathLocalNetWorkUsers = $UNCPathLocalNetWorkUsers
        PathToPasswordStateCredential = ""
    }
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

function Start-TervisVMAndWaitForPort {
    Param(
      [Parameter(Mandatory)]
        $PortNumbertoMonitor,
      [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )
    $IPAddress = $TervisVMObject.DhcpServerv4Lease | select -first 1 -Wait -ExpandProperty ipaddress | select -ExpandProperty IPAddressToString
    Start-VM -ComputerName $TervisVMObject.ComputerName -Name $TervisVMObject.Name
    do{
        Write-Host "Waiting for VM to come online..."
        sleep 3
    }until(Test-NetConnection $IPAddress -Port $PortNumbertoMonitor | ? { $_.TcpTestSucceeded })
}

function Restart-TervisVMAndWaitForPort {
    Param(
      [Parameter(Mandatory)]
        $PortNumbertoMonitor,
      [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )
    $IPAddress = $TervisVMObject.DhcpServerv4Lease | select -first 1 -Wait -ExpandProperty ipaddress | select -ExpandProperty IPAddressToString
    Restart-VM -ComputerName $TervisVMObject.ComputerName -Name $TervisVMObject.Name -force
    do{
        Write-Host "Waiting for VM to shutdown..."
        sleep 3
    }While(Test-NetConnection $IPAddress -Port $PortNumbertoMonitor | ? { $_.TcpTestSucceeded })
    do{
        Write-Host "Waiting for VM to come online..."
        sleep 3
    }until(Test-NetConnection $IPAddress -Port $PortNumbertoMonitor | ? { $_.TcpTestSucceeded })
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

$LastComputerNameCountFromAD = ((get-adcomputer -filter "name -like `"$($ComputerNameSuffixInAD)*`"" | select name | Sort-Object -Descending | select -last 1).name) -replace "inf-sftp",""
$NextComputerNameWithoutEnvironmentPrefix = "sftp"+(($LastComputerNameCountFromAD -as [int]) + 1).tostring("00")
$VM = New-TervisVM -VMNameWithoutEnvironmentPrefix $NextComputerNameWithoutEnvironmentPrefix -VMSizeName $VMSizeName -VMOperatingSystemTemplateName "$VMOperatingSystemTemplateName" -EnvironmentName $Environmentname -Cluster $Cluster -DHCPScopeID $DHCPScopeID -Verbose
$TervisVMObject = $vm | get-tervisVM
$TervisVMObject
}

function Set-TervisSFTPServerConfiguration {

    Param(
      [Parameter(Mandatory)]
        $ServiceName,
      [Parameter(Mandatory)]
        $PathToSFTPDataShare,
      [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )

    Start-TervisVMAndWaitForPort -PortNumbertoMonitor "22" $TervisVMObject

    $IPAddress = $TervisVMObject.DhcpServerv4Lease | select -first 1 -Wait -ExpandProperty ipaddress | select -ExpandProperty IPAddressToString

    $CentOSVMPasswordStateEntry = Get-PasswordStateCredentialFromFile -SecuredAPIkeyFilePath "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\CentOSTemplateDefaultRoot.apikey"
    $secpassword = ConvertTo-SecureString $CentOSVMPasswordStateEntry.Password -AsPlainText -force
    $CentOSVMCredential = New-Object System.Management.Automation.PSCredential ($CentOSVMPasswordStateEntry.UserName, $secpassword)
    New-SSHSession -Credential $CentOSVMCredential -ComputerName $IpAddress -AcceptKey

    $PathToCIFSShareServiceAccountSecureStringFile = "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\inf-sftp.apikey"
    $PasswordstateCredential = Get-PasswordStateCredentialFromFile $PathToCIFSShareServiceAccountSecureStringFile

    $LocalSFTPRepoUserAccount = $ServiceName+"user"
    $LocalSFTPRepoGroup = $ServiceName+"group"

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "yes | yum -y install puppet realmd sssd oddjob oddjob-mkhomedir adcli samba-common"    
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "hostname $($TervisVMObject.name)"
    $fqdn = ((Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "facter | grep fqdn").output -split " ")[2]
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "echo $fqdn > /etc/hostname"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir /etc/puppet/manifests"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install ceh-fstab"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet module install saz-ssh"


        
    $CredentialFileLocation = "/etc/SFTPServiceAccountCredentials.txt"
    $SFTPRootDirectory = "/sftpdata/$LocalSFTPRepoUserAccount/inbound"
    $SFTPCHROOTDirectory = "/sftpdata/$LocalSFTPRepoUserAccount"

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
    options          => 'credentials=$CredentialFileLocation,sec=ntlm,uid=$LocalSFTPRepoUserAccount,gid=$LocalSFTPRepoGroup,dir_mode=0770,file_mode=0660',
    fstype           => 'cifs'
}
class { 'ssh::server':
  storeconfigs_enabled => false,
  options => {
    'HostKey' => ['/etc/ssh/ssh_host_rsa_key','/etc/ssh/ssh_host_ecdsa_key','/etc/ssh/ssh_host_ed25519_key'],
    'SyslogFacility' => 'AUTHPRIV',
    'PasswordAuthentication' => 'yes',
    'Subsystem' => 'sftp internal-sftp',
    'Match Group $LocalSFTPRepoGroup' => {
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
"@

    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $SFTPRootDirectory"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "groupadd $LocalSFTPRepoGroup"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "useradd $LocalSFTPRepoUserAccount -g $LocalSFTPRepoGroup -d /inbound -s /sbin/nologin"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreateSFTPServiceAccountUserNameAndPasswordFile
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "chmod 400 /etc/SFTPServiceAccountCredentials.txt"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "mkdir -p $SFTPRootDirectory"
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $CreatePuppetConfigurationCommand
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/SFTPServer.pp"

    get-sshsession | remove-sshsession
}