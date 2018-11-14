$OracleServerDefinitions = [PSCustomObject][Ordered]@{
    Computername = "ebsdb-prd"
    OVMServerName = "inf-ovmc3n1"
    Memory = "250000"
    MemoryLimit = "260000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "EBSODBEE"
    SID = "PRD"
},
[PSCustomObject][Ordered]@{
    Computername = "ebsapps-prd"
    OVMServerName = "inf-ovmc3n7"
    Memory = "64000"
    MemoryLimit = "128000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "EBSIAS","RPIAS"
    SID = "PRD","PRDRP"
},
[PSCustomObject][Ordered]@{
    Computername = "p-odbee02"
    OVMServerName = "inf-ovmc3n5"
    Memory = "96128"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "OBIAODBEE","OBIEEODBEE"
    SID = "PRDBI","PRDDWH"
},
[PSCustomObject][Ordered]@{
    Computername = "p-weblogic01"
    OVMServerName = "inf-ovmc3n6"
    Memory = "128000"
    MemoryLimit = "128000"
    CPUCount = "16"
    CPUCountLimit = "32"
    PinnedCPUs = "2-17"
    Services = "SOA Weblogic","OBIEE Weblogic","Disco Weblogic"
    SID = "PRDSOS","PRDBI","PRDDisco"
},
[PSCustomObject][Ordered]@{
    Computername = "p-weblogic02"
    OVMServerName = "inf-ovmc3n7"
    Memory = "128000"
    MemoryLimit = "192000"
    CPUCount = "8"
    CPUCountLimit = "8"
    PinnedCPUs = "20-27"
    Services = "RP Weblogic"
    SID = "PRDRP"
},
[PSCustomObject][Ordered]@{
    Computername = "p-infadac"
    OVMServerName = "inf-ovmc3n7"
    Memory = "16384"
    MemoryLimit = "65536"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = "Infadac"
    SID = ""
},
[PSCustomObject][Ordered]@{
    Computername = "zet-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "50000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "20-37"
    Services = "EBSODBEE"
    SID = "SBX"
},
[PSCustomObject][Ordered]@{
    Computername = "zet-ias01"
    OVMServerName = "inf-ovmc3n4"
    Memory = "16000"
    MemoryLimit = "65536"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "EBSIAS"
    SID = "SBX"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-ias01"
    OVMServerName = "inf-ovmc3n4"
    Memory = "31000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "EBSIAS","RPIAS"
    SID = "DEVIAS","DEVRP"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "20-35"
    Services = "EBSODBEE","SOAODBEE","RPODBEE","OBIAODBEE"
    SID = "DEVBI","DEVSOA","DEVRP","DEVDWH"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-odbee02"
    OVMServerName = "inf-ovmc3n2"
    Memory = "30000"
    MemoryLimit = "30000"
    CPUCount = "8"
    CPUCountLimit = "8"
    PinnedCPUs = "20-27"
    Services = "EBSODBEE","SOAODBEE","RPODBEE","OBIAODBEE"
    SID = "DEV","DEVSOA","DEVRP","DEVBI"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-weblogic01"
    OVMServerName = "inf-ovmc3n3"
    Memory = "61000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "OBIEE Weblogic","SOA Weblogic","RP Weblogic","Disco Weblogic"
    SID = "DEVBI","DEVSOA","DEVRP","DEVDISCO"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-weblogic02"
    OVMServerName = "inf-ovmc3n3"
    Memory = "30000"
    MemoryLimit = "30536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "SOA Weblogic"
    SID = "DEVSOA2"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-infadac"
    OVMServerName = "inf-ovmc3n7"
    Memory = "16000"
    MemoryLimit = "65536"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = "Infadac"
    SID = ""
},
[PSCustomObject][Ordered]@{
    Computername = "eps-ias01"
    OVMServerName = "inf-ovmc3n4"
    Memory = "32000"
    MemoryLimit = "64000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "EBSIAS","RPIAS"
    SID = "SIT","SITRP"
},
[PSCustomObject][Ordered]@{
    Computername = "eps-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "32"
    PinnedCPUs = "2-17"
    Services = "EBSODBEE","SOA ODBEE","RP ODBEE","OBIA ODBEE"
    SID = "SIT","SITBI","SITDWH","SITRP"
},
[PSCustomObject][Ordered]@{
    Computername = "eps-weblogic01"
    OVMServerName = "inf-ovmc3n3"
    Memory = "80000"
    MemoryLimit = "256000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "OBIEE Weblogic","SOA Weblogic","RP Weblogic","Disco Weblogic"
    SID = "SITBI","SITSOA","SITRP","SITDISCO"
},
[PSCustomObject][Ordered]@{
    Computername = "eps-infadac"
    OVMServerName = "inf-ovmc3n6"
    Memory = "16000"
    MemoryLimit = "64000"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-17"
    Services = "Infadac"
    SID = ""
},
[PSCustomObject][Ordered]@{
    Computername = "ovmtest"
    OVMServerName = "inf-ovmc3n4"
    Memory = "16000"
    MemoryLimit = "100000"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
}



$OracleClusterNodes = [PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n1"
},
[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n2"
},[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n3"
},[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n4"
},[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n5"
},[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n6"
},[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n7"
},[PSCustomObject][Ordered]@{
    Computername = "inf-ovmc3n8"
}

$TervisOracleServiceBinPaths = [PSCustomObject][Ordered]@{
    SID = "DEV"
    Paths = [PSCustomObject][Ordered]@{
       SOAWLServerBinPath = "/u02/app/applmgr/Middleware_SOA/wlserver_10.3/server/bin"
       SOAUIDomainBinPath = "/u02/app/applmgr/Middleware_SOA/user_projects/domains/DEV_SOAdomain/bin"
       BIWLServerBinPath = "/u01/app/applmgr/Middleware_BI/wlserver_10.3/server/bin"
       BIUIDomainBinPath = "/u01/app/applmgr/Middleware_BI/user_projects/domains/BIDomanin/bin"
       DiscoWLServerBinPath = "/u04/app/applmgr/Middleware_DISCO/wlserver_10.3/server/bin"
       DiscoUIDomainBinPath = "/u04/app/applmgr/Middleware_DISCO/user_projects/domains/DEVDisco_Domain/bin"
       RPWLServerBinPath = "/u03/app/applmgr/Middleware_RP/wlserver_10.3/server/bin"
       RPUIDomainBinPath = "/u03/app/applmgr/Middleware_RP/user_projects/domains/RP_UIDomain/bin"
       InfaDACWLBinPath = "/u01/app/applmgr/BI_INSTALL/HOME_DAC_DEV/dac"
    }
},
[PSCustomObject][Ordered]@{
    SID = "SIT"
    Paths = [PSCustomObject][Ordered]@{
        SOAWLServerBinPath = "/u02/app/applmgr/Middleware_SOA/wlserver_10.3/server/bin"
        SOAUIDomainBinPath = "/u02/app/applmgr/Middleware_SOA/user_projects/domains/SITSOA_Domain/bin"
        BIWLServerBinPath = "/u01/app/applmgr/Middleware_BI/wlserver_10.3/server/bin"
        BIUIDomainBinPath = "/u01/app/applmgr/Middleware_BI/user_projects/domains/BIDomain/bin"
        DiscoWLServerBinPath = "/u04/app/applmgr/Middleware_DISCO/wlserver_10.3/server/bin"
        DiscoUIDomainBinPath = "/u04/app/applmgr/Middleware_DISCO/user_projects/domains/SITDisco_Domain/bin"
        RPWLServerBinPath = "/u03/app/applmgr/Middleware_RP/wlserver_10.3/server/bin"
        RPUIDomainBinPath = "/u03/app/applmgr/Middleware_RP/user_projects/domains/RP_UIDomain/bin"
        InfaDACWLBinPath = "/u01/app/applmgr/BI_INSTALL/HOME_DAC/dac"
    }
}


