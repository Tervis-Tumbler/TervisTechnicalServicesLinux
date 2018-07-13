$OracleServerDefinitions = [PSCustomObject][Ordered]@{
    Computername = "ebsdb-prd"
    OVMServerName = "inf-ovmc3n1"
    Memory = "250000"
    MemoryLimit = "260000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"EBSODBEE"}
},
[PSCustomObject][Ordered]@{
    Computername = "ebsapps-prd"
    OVMServerName = "inf-ovmc3n7"
    Memory = "64000"
    MemoryLimit = "128000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"EBSIAS","RPIAS"}
},
[PSCustomObject][Ordered]@{
    Computername = "p-odbee02"
    OVMServerName = "inf-ovmc3n5"
    Memory = "96128"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"OBIAODBEE","OBIEEODBEE"}
},
[PSCustomObject][Ordered]@{
    Computername = "p-weblogic01"
    OVMServerName = "inf-ovmc3n6"
    Memory = "128000"
    MemoryLimit = "128000"
    CPUCount = "16"
    CPUCountLimit = "32"
    PinnedCPUs = "2-13"
    Services = {"SOA Weblogic","OBIEE Weblogic","Disco Weblogic"}
},
[PSCustomObject][Ordered]@{
    Computername = "p-weblogic02"
    OVMServerName = "inf-ovmc3n7"
    Memory = "128000"
    MemoryLimit = "192000"
    CPUCount = "8"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"RP Weblogic"}
},
[PSCustomObject][Ordered]@{
    Computername = "p-infadac"
    OVMServerName = "inf-ovmc3n7"
    Memory = "16384"
    MemoryLimit = "65536"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"Infadac"}
},
[PSCustomObject][Ordered]@{
    Computername = "zet-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "50000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "20-31"
    Services = {"EBSODBEE"}
},
[PSCustomObject][Ordered]@{
    Computername = "zet-ias01"
    OVMServerName = "inf-ovmc3n4"
    Memory = "16000"
    MemoryLimit = "65536"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"EBSIAS"}
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-ias01"
    OVMServerName = "inf-ovmc3n4"
    Memory = "31000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"EBSIAS","RPIAS"}
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "20-31"
    Services = {"EBSODBEE","SOAODBEE","RPODBEE","OBIAODBEE"}
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-weblogic01"
    OVMServerName = "inf-ovmc3n3"
    Memory = "61000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"OBIEE Weblogic","SOA Weblogic","RP Weblogic","Disco Weblogic"}
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-infadac"
    OVMServerName = "inf-ovmc3n7"
    Memory = "16000"
    MemoryLimit = "65536"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"Infadac"}
},
[PSCustomObject][Ordered]@{
    Computername = "eps-ias01"
    OVMServerName = "inf-ovmc3n4"
    Memory = "32000"
    MemoryLimit = "64000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"EBSIAS","RPIAS"}
},
[PSCustomObject][Ordered]@{
    Computername = "eps-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "32"
    PinnedCPUs = "2-13"
    Services = {"EBSODBEE","SOA ODBEE","RP ODBEE","OBIA ODBEE"}
},
[PSCustomObject][Ordered]@{
    Computername = "eps-weblogic01"
    OVMServerName = "inf-ovmc3n3"
    Memory = "80000"
    MemoryLimit = "256000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"OBIEE Weblogic","SOA Weblogic","RP Weblogic","Disco Weblogic"}
},
[PSCustomObject][Ordered]@{
    Computername = "eps-infadac"
    OVMServerName = "inf-ovmc3n6"
    Memory = "16000"
    MemoryLimit = "64000"
    CPUCount = "4"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
    Services = {"Infadac"}
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