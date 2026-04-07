# BlueHammer

## Overview

BlueHammer is a local privilege escalation (LPE) proof-of-concept targeting Windows Defender's
signature update mechanism. It chains multiple TOCTOU race conditions to leak the SAM database
through a Volume Shadow Copy, extracts NTLM hashes, and escalates from standard user to SYSTEM.

Originally authored by Tom Gallagher, Igor Tsyganskiy, and Jeremy Tinder (per source code comments).

## Red Team Analysis

This repository was identified and analyzed by the Red Team for
research purposes. The original PoC contained multiple bugs that prevented reliable execution.
This fork includes bug fixes, detection rules, and lab testing documentation.

### What was done

- Full static analysis of the exploit chain (7 stages)
- Identified and fixed 9 bugs in the original source code
- Added `--force` flag to bypass Windows Update API polling for lab testing
- Hardened update filter to distinguish signature updates (KB2267602) from platform updates (KB4052623)
- Lab tested on Windows 10 VM (MalDev environment) with EDR/NDR monitoring
- Developed 7 Sigma detection rules and 4 YARA rules
- Produced executive summary and full technical report

## Exploit Chain Summary

| Stage | Description | Lab Validated |
|---|---|---|
| 1 | Poll Windows Update API for pending Defender signature update | Yes |
| 2 | Download update package from Microsoft CDN, extract .vdm files | Yes |
| 3 | Drop EICAR test file, oplock RstrtMgr.dll, trigger VSS creation | Yes |
| 4 | Register Cloud Files sync root, identify MsMpEng.exe by PID, freeze via oplock | Yes |
| 5 | RPC to Defender update endpoint, oplock .vdm, junction + object manager symlink to redirect read to SAM via VSS | Partial — RPC version gate |
| 6 | Decrypt SAM hashes using LSA boot key, change passwords via SamiChangePasswordUser, logon, restore | Not reached |
| 7 | Create temporary SYSTEM service, spawn conhost.exe in user session | Not reached |

Stages 1-4 (the novel primitives) are fully validated. Stage 5 requires a natural definition
version gap between what is installed and what the CDN serves. This condition exists on any
machine where definitions are even slightly out of date, but is difficult to simulate in a
lab with freshly updated definitions. Stages 6-7 use well-documented credential manipulation
and service creation techniques.

## Bug Fixes Applied

| # | Location | Bug | Fix |
|---|---|---|---|
| 1 | Line 688 | `hint2` not nulled after `InternetCloseHandle` | Changed to `hint2 = NULL` |
| 2 | Line 3380 | Cleanup checks `hint` twice instead of `hint`/`hint2` | Changed guard to `if(hint2)` |
| 3 | Lines 3384-3385 | `UnmapViewOfFile` on `malloc`'d buffer | Removed dead cleanup code |
| 4 | Line 2188 | `ZeroMemory` size `size+1` instead of `size*2+1` | Fixed buffer size |
| 5 | Lines 2113, 2117 | `sizeof(data)` is pointer size (8) not array size (7) | Explicit constant `DATA_LEN = 7` |
| 6 | Line 1294 | VSS finder thread infinite spin with no sleep | Added `Sleep(50)` between retries |
| 7 | Line 1863 | Crypto handles leaked in `UnprotectAES` | Added `CryptDestroyKey`/`CryptReleaseContext` |
| 8 | Line 2049 | Crypto key leaked in `UnprotectDES` | Added `CryptDestroyKey` |
| 9 | Line 1724 | `GetExitCodeThread` called before thread completes (returns `STILL_ACTIVE`) | Added `WaitForSingleObject` before exit code check |

## Build

**Requirements:**
- Visual Studio 2022 (v143 toolset)
- Windows SDK 10.0.26100.0
- x64 target platform

```
Open FunnyApp.sln
Select: Release | x64
Build -> Build Solution
Output: x64\Release\FunnyApp.exe
```

**Note:** The pre-built `x64\Release\FunnyApp.exe` is from the original repository and is
untrusted. Always build from source.

## Usage

```
FunnyApp.exe              Normal mode — waits for pending signature update via Windows Update API
FunnyApp.exe --force      Force mode — skips update check, downloads directly from CDN
```

Normal mode is recommended. It only proceeds when a genuine definition version gap exists,
which guarantees the RPC call will succeed. Force mode is useful for lab testing but may fail
with `0x8050A003` if installed definitions already match the CDN version.

### Prerequisites

- Windows Defender real-time protection must be ON
- A pending signature definition update must exist (normal mode handles this automatically)
- Standard user privileges (no admin required for the exploit itself)
- Internet connectivity to `go.microsoft.com` (Microsoft CDN)

### Lab Setup Tips

To create a definition version gap for testing:
1. Disable Tamper Protection via Windows Security GUI
2. Roll back definitions: `MpCmdRun.exe -RemoveDefinitions -All`
3. Restore definitions: `MpCmdRun.exe -SignatureUpdate`
4. Wait for next Microsoft definition publish (every 2-4 hours)
5. Run `FunnyApp.exe` — it will detect the pending update automatically

## Repository Structure

```
FunnyApp.cpp                    Main exploit source (3,450+ lines)
FunnyApp.sln / .vcxproj         Visual Studio 2022 project
windefend.idl                   MIDL interface definition for WD RPC
windefend_c.c / _s.c / _h.h    MIDL-generated RPC stubs and header
offreg.h / offreg.lib           Microsoft Offline Registry Library
detection_rules/
  sigma/
    bluehammer_samlib_load.yml           Non-LSASS process loading samlib.dll
    bluehammer_rapid_password_change.yml Password change-logon-restore cycle
    bluehammer_junction_basenamed.yml    Junction to BaseNamedObjects
    bluehammer_temp_service_creation.yml GUID-named temporary service
    bluehammer_oplock_rstrtmgr.yml       Exclusive handle on RstrtMgr.dll
    bluehammer_cloudfiles_abuse.yml      Cloud Files API by non-provider
    bluehammer_lsa_bootkey_access.yml    LSA boot key registry access
    bluehammer_defender_rpc_call.yml     Non-Defender RPC to IMpService
  yara/
    bluehammer.yar                       4 rules: exact match + 3 variant rules
reports/
  EXECUTIVE_SUMMARY.md                   For security leadership / CISO
  TECHNICAL_REPORT.md                    For SOC / detection engineering / IR
LAB_IOC_OBSERVATION_GUIDE.md             Stage-by-stage IoC checklist for lab testing
```

## MITRE ATT&CK Coverage

| Technique | Description | Stage |
|---|---|---|
| T1068 | Exploitation for Privilege Escalation | 3-5 |
| T1543.003 | Windows Service | 7 |
| T1562.001 | Disable or Modify Tools | 4 |
| T1574.005 | Executable Installer File Permissions Abuse | 5 |
| T1003.002 | SAM | 6 |
| T1552.002 | Credentials in Registry | 6 |
| T1098 | Account Manipulation | 6 |
| T1569.002 | Service Execution | 7 |
| T1005 | Data from Local System | 5 |

## Key Findings

1. **No malware, C2, or reverse shells.** The only network connection is to Microsoft's
   legitimate update CDN. No data exfiltration, no beaconing, no persistence.

2. **Novel Cloud Files API abuse.** Using `CfRegisterSyncRoot` + callbacks to identify
   security processes by PID and selectively freeze them is creative and currently
   undermonitored across the industry.

3. **Composable primitives.** The exploit contains 6 independent techniques (oplock TOCTOU,
   Cloud Files freeze, junction+symlink chain, unprivileged VSS creation, local pass-the-hash
   via SamiChangePasswordUser, temp service escalation) that can be recombined against
   different targets even after Microsoft patches this specific vulnerability.

4. **Detection gaps exist.** Cloud Files sync root registration, object manager symlink
   creation, and `SamiChangePasswordUser` from non-LSASS processes are not monitored by
   default in most environments.
