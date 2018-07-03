$OracleServerDefinitions = [PSCustomObject][Ordered]@{
    Computername = "zet-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "50000"
    MemoryLimit = "65536"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "20-31"
},
[PSCustomObject][Ordered]@{
    Computername = "dlt-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "20-31"
},
[PSCustomObject][Ordered]@{
    Computername = "eps-odbee01"
    OVMServerName = "inf-ovmc3n2"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
},
[PSCustomObject][Ordered]@{
    Computername = "ovmtest"
    OVMServerName = "inf-ovmc3n4"
    Memory = "100000"
    MemoryLimit = "250000"
    CPUCount = "16"
    CPUCountLimit = "16"
    PinnedCPUs = "2-13"
}


