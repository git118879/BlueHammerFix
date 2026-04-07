/*
    BlueHammer — Windows Defender LPE PoC
    Detects compiled BlueHammer binaries and variants.
    Targets both the exact PoC and modified versions reusing the same primitives.
*/

rule BlueHammer_Exact
{
    meta:
        description = "Detects the exact BlueHammer PoC binary based on unique string combinations"
        author = "Red Team"
        date = "2026-04-06"
        severity = "critical"
        mitre_attack = "T1068, T1003.002, T1543.003, T1574.005"

    strings:
        // Unique string artifacts
        $provider   = "IHATEMICROSOFT" wide ascii
        $password   = "$PWNed666!!!WDFAIL" wide ascii
        $rpc_uuid   = "c503f532-443a-4c69-8300-ccd1fbdb3839" wide ascii
        $rpc_endpt  = "IMpService77BDAF73-B396-481F-9042-AD358843EC24" wide ascii
        $useragent  = "Chrome/141.0.0.0" wide ascii
        $update_url = "LinkID=121721" wide ascii

        // Reversed EICAR string (stored reversed to avoid AV detection at rest)
        $eicar_rev  = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$" ascii

        // Debug/status messages unique to this PoC
        $msg1       = "Waiting for callback..." ascii wide
        $msg2       = "WD is frozen and the new VSS can be used." ascii wide
        $msg3       = "Exploit succeeded." ascii wide
        $msg4       = "SAM file written at" ascii wide
        $msg5       = "Defender flagged." ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($provider and $rpc_uuid) or
            ($password and $eicar_rev) or
            ($rpc_endpt and $msg3) or
            (3 of ($msg*) and $rpc_uuid)
        )
}

rule BlueHammer_Variant_DefenderOplock
{
    meta:
        description = "Detects variants reusing the Defender oplock+junction+symlink primitive"
        author = "Red Team"
        date = "2026-04-06"
        severity = "high"
        mitre_attack = "T1068, T1574.005"

    strings:
        // RPC interface UUID for Windows Defender MpService
        $rpc_uuid    = "c503f532-443a-4c69-8300-ccd1fbdb3839" wide ascii

        // ALPC endpoint pattern
        $rpc_endpt   = "IMpService" wide ascii nocase

        // Junction target used in the exploit
        $junction    = "\\BaseNamedObjects\\Restricted" wide ascii

        // VDM file name used as symlink pivot
        $vdm        = "mpasbase.vdm" wide ascii

        // Defender definition updates path
        $defpath    = "Definition Updates" wide ascii

        // FSCTL constants (as immediate values in compiled code)
        // FSCTL_REQUEST_BATCH_OPLOCK = 0x00090008
        $oplock_ctl = { 08 00 09 00 }
        // FSCTL_SET_REPARSE_POINT = 0x000900A4
        $reparse_ctl = { A4 00 09 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $rpc_uuid and
        (
            ($junction and $vdm) or
            ($junction and $reparse_ctl) or
            ($oplock_ctl and $reparse_ctl and $rpc_endpt) or
            ($defpath and $vdm and $oplock_ctl)
        )
}

rule BlueHammer_Variant_SAMDump_SamiChange
{
    meta:
        description = "Detects variants reusing the SAM dump + SamiChangePasswordUser technique"
        author = "Red Team"
        date = "2026-04-06"
        severity = "high"
        mitre_attack = "T1003.002, T1098"

    strings:
        // SAM database structure offsets (compiled as immediates)
        $sam_offset_cc = "SAM\\Domains\\Account" wide ascii
        $sam_v_value   = { 56 00 00 00 }  // "V" value name in registry query

        // SamiChangePasswordUser import
        $sami_change   = "SamiChangePasswordUser" ascii
        $samlib        = "samlib.dll" wide ascii nocase

        // LSA boot key components
        $lsa_jd        = "\\Control\\Lsa\\JD" wide ascii
        $lsa_skew      = "\\Control\\Lsa\\Skew1" wide ascii
        $lsa_gbg       = "\\Control\\Lsa\\GBG" wide ascii
        $lsa_data      = "\\Control\\Lsa\\Data" wide ascii

        // Offline registry API
        $offreg_open   = "OROpenHive" ascii
        $offreg_get    = "ORGetValue" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($sami_change and $samlib and $sam_offset_cc) or
            ($sami_change and 3 of ($lsa_*)) or
            ($offreg_open and $offreg_get and $sami_change) or
            (4 of ($lsa_*) and $sam_offset_cc)
        )
}

rule BlueHammer_Variant_CloudFilesFreeze
{
    meta:
        description = "Detects variants reusing the Cloud Files API to identify and freeze security processes"
        author = "Red Team"
        date = "2026-04-06"
        severity = "high"
        mitre_attack = "T1562.001"

    strings:
        // Cloud Files API imports
        $cf_register    = "CfRegisterSyncRoot" ascii
        $cf_connect     = "CfConnectSyncRoot" ascii
        $cf_execute     = "CfExecute" ascii

        // Combined with Defender PID lookup
        $windefend_svc  = "WinDefend" wide ascii
        $query_svc      = "QueryServiceStatusEx" ascii

        // Combined with oplock
        $oplock_ctl     = { 08 00 09 00 }  // FSCTL_REQUEST_BATCH_OPLOCK

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $cf_register and $cf_connect and
        (
            ($windefend_svc and $query_svc) or
            ($cf_execute and $oplock_ctl) or
            ($windefend_svc and $oplock_ctl)
        )
}
