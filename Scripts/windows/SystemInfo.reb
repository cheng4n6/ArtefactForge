Description: ArtefactForge system summary
Author: ArtefactForge
Version: 1
Id: 8f2c1a44-6d33-4f7e-9a11-5c0e2b7d4419
# Only the values the system summary needs. Deliberately its own batch rather than reading what
# RECmd_SystemHives produced: the summary then works whether or not that module was selected, and
# cannot break when its output changes.
#
# ControlSet* rather than ControlSet001 - the current set is whichever Select\Current names, and on
# a machine that has failed over it is not always 001.
Keys:
    -
        Description: ComputerName
        HiveType: SYSTEM
        Category: Identity
        KeyPath: ControlSet*\Control\ComputerName\ComputerName
        ValueName: ComputerName
        Recursive: false
        Comment: Host name as the machine knows it
    -
        Description: Domain
        HiveType: SYSTEM
        Category: Identity
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        ValueName: Domain
        Recursive: false
        Comment:
    -
        Description: NVDomain
        HiveType: SYSTEM
        Category: Identity
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        ValueName: NV Domain
        Recursive: false
        Comment:
    -
        Description: TcpipHostname
        HiveType: SYSTEM
        Category: Identity
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        ValueName: Hostname
        Recursive: false
        Comment:
    -
        Description: ProductType
        HiveType: SYSTEM
        Category: Identity
        KeyPath: ControlSet*\Control\ProductOptions
        ValueName: ProductType
        Recursive: false
        Comment: WinNT workstation, ServerNT server, LanmanNT domain controller
    -
        Description: CurrentControlSet
        HiveType: SYSTEM
        Category: Identity
        KeyPath: Select
        ValueName: Current
        Recursive: false
        Comment:
    -
        Description: TimeZoneKeyName
        HiveType: SYSTEM
        Category: Time
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: TimeZoneKeyName
        Recursive: false
        Comment: Everything ArtefactForge writes is UTC; this reconciles it with local time
    -
        Description: TimeZoneStandardName
        HiveType: SYSTEM
        Category: Time
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: StandardName
        Recursive: false
        Comment:
    -
        Description: TimeZoneBias
        HiveType: SYSTEM
        Category: Time
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: Bias
        Recursive: false
        Comment: Minutes to add to local time to get UTC
    -
        Description: TimeZoneActiveBias
        HiveType: SYSTEM
        Category: Time
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: ActiveTimeBias
        Recursive: false
        Comment: Bias in force at the time of capture, daylight saving included
    -
        Description: TimeZoneDaylightBias
        HiveType: SYSTEM
        Category: Time
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: DaylightBias
        Recursive: false
        Comment:
    -
        Description: ShutdownTime
        HiveType: SYSTEM
        Category: Time
        KeyPath: ControlSet*\Control\Windows
        ValueName: ShutdownTime
        Recursive: false
        Comment: Last clean shutdown, FILETIME
    -
        Description: SystemManufacturer
        HiveType: SYSTEM
        Category: Hardware
        KeyPath: ControlSet*\Control\SystemInformation
        ValueName: SystemManufacturer
        Recursive: false
        Comment:
    -
        Description: SystemProductName
        HiveType: SYSTEM
        Category: Hardware
        KeyPath: ControlSet*\Control\SystemInformation
        ValueName: SystemProductName
        Recursive: false
        Comment: Model, and usually enough to tell a VM from metal
    -
        Description: BIOSVersion
        HiveType: SYSTEM
        Category: Hardware
        KeyPath: ControlSet*\Control\SystemInformation
        ValueName: BIOSVersion
        Recursive: false
        Comment:
    -
        Description: BIOSReleaseDate
        HiveType: SYSTEM
        Category: Hardware
        KeyPath: ControlSet*\Control\SystemInformation
        ValueName: BIOSReleaseDate
        Recursive: false
        Comment:
    -
        Description: NetworkInterface
        HiveType: SYSTEM
        Category: Network
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        Recursive: false
        Comment: Every value under each interface - addresses, gateway, DNS, DHCP lease
    -
        Description: ProductName
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ProductName
        Recursive: false
        Comment:
    -
        Description: DisplayVersion
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: DisplayVersion
        Recursive: false
        Comment: 22H2 and the like; absent before Windows 10 20H2
    -
        Description: ReleaseId
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ReleaseId
        Recursive: false
        Comment:
    -
        Description: CurrentBuild
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentBuild
        Recursive: false
        Comment:
    -
        Description: UBR
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: UBR
        Recursive: false
        Comment: Update build revision - the patch level after the build number
    -
        Description: EditionID
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: EditionID
        Recursive: false
        Comment:
    -
        Description: InstallationType
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallationType
        Recursive: false
        Comment: Client, Server, or Server Core
    -
        Description: InstallDate
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallDate
        Recursive: false
        Comment: Unix epoch seconds
    -
        Description: RegisteredOwner
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: RegisteredOwner
        Recursive: false
        Comment:
    -
        Description: RegisteredOrganization
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: RegisteredOrganization
        Recursive: false
        Comment:
    -
        Description: BuildLabEx
        HiveType: SOFTWARE
        Category: OperatingSystem
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildLabEx
        Recursive: false
        Comment:
    -
        Description: LastLoggedOnUser
        HiveType: SOFTWARE
        Category: Accounts
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: LastLoggedOnUser
        Recursive: false
        Comment:
    -
        Description: LastLoggedOnSAMUser
        HiveType: SOFTWARE
        Category: Accounts
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: LastLoggedOnSAMUser
        Recursive: false
        Comment:
    -
        Description: AutoAdminLogon
        HiveType: SOFTWARE
        Category: Accounts
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: AutoAdminLogon
        Recursive: false
        Comment: A stored plaintext password sits alongside this when it is 1
    -
        Description: DefaultUserName
        HiveType: SOFTWARE
        Category: Accounts
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: DefaultUserName
        Recursive: false
        Comment:
    -
        Description: UserProfile
        HiveType: SOFTWARE
        Category: Accounts
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: ProfileImagePath
        Recursive: false
        Comment: The key name is the account SID; the machine SID is its prefix
    -
        Description: NetworkProfile
        HiveType: SOFTWARE
        Category: NetworkHistory
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        Recursive: false
        Comment: Every network this machine has joined, with first and last connect
