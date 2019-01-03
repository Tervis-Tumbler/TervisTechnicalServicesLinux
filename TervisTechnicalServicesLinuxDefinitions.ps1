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
    Environment = "Production"
    ServiceUserAccount = "oracle"
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
    Environment = "Production"
    ServiceUserAccount = "applmgr"
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
    Environment = "Production"
    ServiceUserAccount = "oracle"
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
    SID = "PRDSOA","PRDBI","PRDDisco"
    Environment = "Production"
    ServiceUserAccount = "applmgr"
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
    Environment = "Production"
    ServiceUserAccount = "applmgr"
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
    Environment = "Production"
    ServiceUserAccount = "applmgr"
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
    Environment = "Zeta"
    ServiceUserAccount = "oracle"
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
    Environment = "Zeta"
    ServiceUserAccount = "applmgr"
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
    SID = "DEV","DEVRP"
    Environment = "Delta"
    ServiceUserAccount = "applmgr"
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
    SID = "DEV","DEVBI","DEVSOA","DEVRP","DEVDWH"
    Environment = "Delta"
    ServiceUserAccount = "oracle"
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
    SID = "DEVSOA12"
    Environment = "Delta"
    ServiceUserAccount = "oracle"
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
    Environment = "Delta"
    ServiceUserAccount = "applmgr"
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
    SID = "DEVSOA12"
    Environment = "Delta"
    ServiceUserAccount = "applmgr"
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
    SID = "DEVINFADAC"
    Environment = "Delta"
    ServiceUserAccount = "applmgr"
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
    Environment = "Epsilon"
    ServiceUserAccount = "applmgr"
},
[PSCustomObject][Ordered]@{
    Computername = "eps-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "32"
    PinnedCPUs = "2-17"
    Services = "EBSODBEE","SOAODBEE","RPODBEE","OBIAODBEE"
    SID = "SIT","SITBI","SITDWH","SITRP","SITSOA"
    Environment = "Epsilon"
    ServiceUserAccount = "oracle"
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
    Environment = "Epsilon"
    ServiceUserAccount = "applmgr"
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
    SID = "SITINFADAC"
    Environment = "Epsilon"
    ServiceUserAccount = "applmgr"
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
    SID = "DEVINFADAC"
    Paths = [PSCustomObject][Ordered]@{
       InfaDACWLBinPath = "/u01/app/applmgr/BI_INSTALL/HOME_DAC_DEV/dac"
    }
},
[PSCustomObject][Ordered]@{
    SID = "DEVRP"
    Paths = [PSCustomObject][Ordered]@{
        RPWLServerBinPath = "/u03/app/applmgr/Middleware_RP/wlserver_10.3/server/bin"
        RPUIDomainBinPath = "/u03/app/applmgr/Middleware_RP/user_projects/domains/RP_UIDomain/bin"
        RPUIServerConfigPath = "/u03/app/applmgr/Middleware_RP/user_projects/domains/RP_UIDomain/config"
    }
},
[PSCustomObject][Ordered]@{
    SID = "DEVSOA"
    Paths = [PSCustomObject][Ordered]@{
        SOAWLServerBinPath = "/u02/app/applmgr/Middleware_SOA/wlserver_10.3/server/bin"
        SOAUIDomainBinPath = "/u02/app/applmgr/Middleware_SOA/user_projects/domains/DEV_SOAdomain/bin"
        SOAUIServerConfigPath = "/u02/app/applmgr/Middleware_SOA/user_projects/domains/DEV_SOAdomain/config"
     }
},
[PSCustomObject][Ordered]@{
    SID = "DEVBI"
    Paths = [PSCustomObject][Ordered]@{
        BIWLServerBinPath = "/u01/app/applmgr/Middleware_BI/wlserver_10.3/server/bin"
        BIUIDomainBinPath = "/u01/app/applmgr/Middleware_BI/user_projects/domains/BIDomanin/bin"
        BIUIServerConfigPath = "/u01/app/applmgr/Middleware_BI/user_projects/domains/BIDomanin/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "DEVSOA12"
    Paths = [PSCustomObject][Ordered]@{
        SOAWLServerBinPath = "/soabin/app/applmgr/Middleware_SOA12/wlserver/server/bin"
        SOAUIDomainBinPath = "/soabin/app/applmgr/Middleware_SOA12/user_projects/domains/DEV_SOA12domain/bin"
        SOAUIServerConfigPath = "/soabin/app/applmgr/Middleware_SOA12/user_projects/domains/DEV_SOA12domain/config"
     }
},
[PSCustomObject][Ordered]@{
    SID = "DEVDISCO"
    Paths = [PSCustomObject][Ordered]@{
        DiscoWLServerBinPath = "/u04/app/applmgr/Middleware_DISCO/wlserver_10.3/server/bin"
        DiscoUIDomainBinPath = "/u04/app/applmgr/Middleware_DISCO/user_projects/domains/DEVDisco_Domain/bin"
        DiscoUIServerConfigPath = "/u04/app/applmgr/Middleware_DISCO/user_projects/domains/DEVDisco_Domain/config"
      }
    ServiceDetails = [PSCustomObject][Ordered]@{

    }
},
[PSCustomObject][Ordered]@{
    SID = "SITINFADAC"
    Paths = [PSCustomObject][Ordered]@{
        InfaDACWLBinPath = "/u01/app/applmgr/BI_INSTALL/HOME_DAC/dac"
    }
},
[PSCustomObject][Ordered]@{
    SID = "SITDISCO"
    Paths = [PSCustomObject][Ordered]@{
        DiscoWLServerBinPath = "/u04/app/applmgr/Middleware_DISCO/wlserver_10.3/server/bin"
        DiscoUIDomainBinPath = "/u04/app/applmgr/Middleware_DISCO/user_projects/domains/SITDisco_Domain/bin"
        DIscoUIServerConfigPath = "/u04/app/applmgr/Middleware_DISCO/user_projects/domains/SITDisco_Domain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "SITSOA"
    Paths = [PSCustomObject][Ordered]@{
        SOAWLServerBinPath = "/u02/app/applmgr/Middleware_SOA/wlserver_10.3/server/bin"
        SOAUIDomainBinPath = "/u02/app/applmgr/Middleware_SOA/user_projects/domains/SITSOA_Domain/bin"
        SOAUIServerConfigPath = "/u02/app/applmgr/Middleware_SOA/user_projects/domains/SITSOA_Domain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "SITBI"
    Paths = [PSCustomObject][Ordered]@{
        BIWLServerBinPath = "/u01/app/applmgr/Middleware_BI/wlserver_10.3/server/bin"
        BIUIDomainBinPath = "/u01/app/applmgr/Middleware_BI/user_projects/domains/BIDomain/bin"
        BIUIServerConfigPath = "/u01/app/applmgr/Middleware_BI/user_projects/domains/BIDomain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "SITRP"
    Paths = [PSCustomObject][Ordered]@{
        RPWLServerBinPath = "/u03/app/applmgr/Middleware_RP/wlserver_10.3/server/bin"
        RPUIDomainBinPath = "/u03/app/applmgr/Middleware_RP/user_projects/domains/RP_UIDomain/bin"
        RPUIServerConfigPath = "/u03/app/applmgr/Middleware_RP/user_projects/domains/RP_UIDomain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "PRDINFADAC"
    Paths = [PSCustomObject][Ordered]@{
        InfaDACWLBinPath = "/infadacbin/app/applmgr/BI_INSTALL/product/HOME_DAC/dac"
    }
},
[PSCustomObject][Ordered]@{
    SID = "PRDDISCO"
    Paths = [PSCustomObject][Ordered]@{
        DiscoWLServerBinPath = "/discobin/Middleware_DISCO/wlserver_10.3/server/bin"
        DiscoUIDomainBinPath = "/discobin/Middleware_DISCO/user_projects/domains/PRD_DiscoDomain/bin"
        DiscoUIServerConfigPath = "/discobin/Middleware_DISCO/user_projects/domains/PRD_DiscoDomain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "PRDSOA"
    Paths = [PSCustomObject][Ordered]@{
        SOAWLServerBinPath = "/soabin/Middleware_SOA/wlserver_10.3/server/bin"
        SOAUIDomainBinPath = "/soabin/Middleware_SOA/user_projects/domains/PRDSOA_Domain/bin"
        SOAUIServerConfigPath = "/soabin/Middleware_SOA/user_projects/domains/PRDSOA_Domain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "PRDBI"
    Paths = [PSCustomObject][Ordered]@{
        BIWLServerBinPath = "/obieebin/Middleware_BI/wlserver_10.3/server/bin"
        BIUIDomainBinPath = "/obieebin/Middleware_BI/user_projects/domains/PRD_BIDomain/bin"
        BIUIServerConfigPath = "/obieebin/Middleware_BI/user_projects/domains/PRD_BIDomain/config"
      }
},
[PSCustomObject][Ordered]@{
    SID = "PRDRP"
    Paths = [PSCustomObject][Ordered]@{
        RPWLServerBinPath = "/rpbin/Middleware_RP/wlserver_10.3/server/bin"
        RPUIDomainBinPath = "/rpbin/Middleware_RP/user_projects/domains/RP_UIDomain/bin"
        RPUIServerConfigPath = "/rpbin/Middleware_RP/user_projects/domains/RP_UIDomain/config"
      }
}

#/soabin/app/applmgr/Middleware_SOA12/user_projects/domains/DEV_SOA12domain/bin/