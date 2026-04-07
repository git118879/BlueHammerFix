# BlueHammer — Technical Analysis Report

**Classification:** CONFIDENTIAL — Internal Use Only
**Date:** April 6, 2026
**Prepared by:** Red Team, Security Engineering
**Audience:** SOC Engineers, Detection Engineering, Incident Response, Threat Intelligence

---

## Table of Contents

1. [Summary](#1-summary)
2. [Repository Overview](#2-repository-overview)
3. [Exploit Chain — Detailed Walkthrough](#3-exploit-chain--detailed-walkthrough)
4. [Bug Inventory and Fixes](#4-bug-inventory-and-fixes)
5. [Reusable Exploitation Primitives](#5-reusable-exploitation-primitives)
6. [Indicators of Compromise](#6-indicators-of-compromise)
7. [Detection Rules](#7-detection-rules)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Lab Execution Guidance](#9-lab-execution-guidance)
10. [References](#10-references)

---

## 1. Summary

BlueHammer is a local privilege escalation (LPE) exploit targeting Windows Defender's
signature update mechanism. It chains multiple TOCTOU race conditions to leak the SAM
database through a Volume Shadow Copy, then extracts NTLM hashes and escalates to SYSTEM
via temporary service creation.

**Key characteristics:**
- Runs as standard user, escalates to SYSTEM
- No external C2, no malware download, no reverse shell
- Only outbound connection: Microsoft's legitimate Defender update CDN
- Passwords restored after use — minimal forensic footprint
- Source attributed to Tom Gallagher, Igor Tsyganskiy, and Jeremy Tinder (per code comments)
- PGP-signed README, publicly hosted on GitHub

---

## 2. Repository Overview

| File | Purpose |
|---|---|
| `FunnyApp.cpp` | Main exploit source (~3,450 lines) |
| `FunnyApp.sln` / `.vcxproj` | Visual Studio 2022 project (v143 toolset) |
| `windefend.idl` | MIDL interface definition for WD RPC |
| `windefend_c.c` | MIDL-generated client stub (~2MB, auto-generated) |
| `windefend_s.c` | MIDL-generated server stub (~1.9MB, auto-generated) |
| `windefend_h.h` | MIDL-generated header |
| `offreg.h` / `offreg.lib` | Microsoft Offline Registry Library (for reading SAM hive offline) |
| `x64/Release/FunnyApp.exe` | Pre-built binary (388KB) — **untrusted, build from source** |

**Build requirements:** Visual Studio 2022, Windows SDK 10.0.26100.0, x64 Release configuration.

**Linked libraries:** `wininet.lib`, `ktmw32.lib`, `Shlwapi.lib`, `Rpcrt4.lib`, `ntdll.lib`,
`Cabinet.lib`, `Wuguid.lib`, `CldApi.lib`, `offreg.lib` (project-local)

---

## 3. Exploit Chain — Detailed Walkthrough

### Stage 0: Entry Point Dispatch (wmain, line 2881)

The binary serves dual purpose:
- **First run (standard user):** Executes the full exploit chain
- **Second run (SYSTEM via service):** Reads session ID from argv[1], spawns `conhost.exe`
  in that session via `CreateProcessAsUser` with a duplicated SYSTEM token

Detection: `IsRunningAsLocalSystem()` (line 2825) checks process token SID against
`WinLocalSystemSid`.

### Stage 1: Defender Update Polling (lines 3036-3044)

Polls Windows Update Agent COM API (`Microsoft.Update.Session`) every 30 seconds,
searching for updates categorized as both `"Microsoft Defender Antivirus"` AND
`"Definition Updates"`. The exploit cannot proceed without a pending update.

**Dependency:** If Defender definitions are current, the exploit blocks here indefinitely.
In lab testing, you may need to block auto-update or roll back definitions to create
a pending state.

**COM flow:**
```
CoCreateInstance(Microsoft.Update.Session)
  -> IUpdateSession::CreateUpdateSearcher
    -> IUpdateSearcher::Search("")
      -> ISearchResult::get_Updates
        -> iterate: check IUpdate::get_Categories for matching category names
```

### Stage 2: Update Package Download (GetUpdateFiles, lines 599-783)

Downloads Defender update stub from Microsoft CDN:
```
InternetOpen(L"Chrome/141.0.0.0", INTERNET_OPEN_TYPE_DIRECT, ...)
InternetOpenUrl(hint, L"https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64", ...)
```

The downloaded file is `mpam-fe.exe` (Microsoft's Defender update self-extractor, ~100MB).
The PoC does NOT execute it. Instead:

1. `GetCabFileFromBuff()` (line 465) parses the PE header manually, walks section table,
   finds `.rsrc` section, traverses resource directory tree to extract embedded cabinet data
2. FDI (Cabinet API) extracts cab contents into memory via custom callbacks:
   - `CUST_FNOPEN/READ/WRITE/SEEK/CLOSE` — all operate on in-memory buffers, no disk I/O
   - `CUST_FNFDINOTIFY` — captures each file, skips `MpSigStub.exe`
3. Returns linked list of `UpdateFiles` structs (filename, buffer, size)

**Network IoC:** User-Agent `Chrome/141.0.0.0` from a non-browser process is the strongest
network-level indicator. The destination is legitimate Microsoft infrastructure.

### Stage 3: VSS Trigger via EICAR + Oplock (TriggerWDForVS, lines 1593-1753)

**Objective:** Force Defender to create a Volume Shadow Copy (requires SYSTEM privileges
that the exploit doesn't have) by triggering its remediation path.

**Step 3a — EICAR drop:**
```cpp
char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
rev(eicar); // reverse to standard EICAR string
```
Written to `%TEMP%\<GUID>\foo.exe`. Stored reversed to avoid Defender flagging the
binary at rest.

**Step 3b — RstrtMgr.dll oplock:**
```cpp
hlock = CreateFile(rstmgr, GENERIC_READ | SYNCHRONIZE, NULL, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, ...);
```
Opens `%windir%\System32\RstrtMgr.dll` exclusively with a batch oplock. When Defender
remediation loads this DLL (Restart Manager checks during quarantine), the oplock pauses
Defender mid-operation while VSS snapshot is being created.

**Step 3c — Trigger scan:**
EICAR file is re-opened to trigger Defender real-time scan. Defender detects, initiates
remediation, loads `RstrtMgr.dll`, hits oplock.

**Step 3d — VSS detection:**
`ShadowCopyFinderThread` (line 1161) polls `\Device` via `NtOpenDirectoryObject` +
`NtQueryDirectoryObject`, comparing against baseline VSS list. Detects new
`HarddiskVolumeShadowCopy*` entries.

### Stage 4: Cloud Files API — Selective Process Freezing (FreezeVSS, lines 1455-1590)

**Objective:** Keep Defender frozen on the VSS snapshot while the exploit completes.

1. `CfRegisterSyncRoot()` — registers exploit directory as Cloud Files sync root
   - Provider: `L"IHATEMICROSOFT"`, Version: `L"1.0"`
   - Policy: `CF_HYDRATION_POLICY_PARTIAL` with `CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED`

2. Creates placeholder `.lock` file (GUID-named)

3. `CfConnectSyncRoot()` with flags:
   - `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO` — enables PID identification in callbacks
   - `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH`

4. Callback `CfCallbackFetchPlaceHolders` (line 1370):
   - Checks `CallbackInfo->ProcessInfo->ProcessId` against `GetWDPID()`
   - `GetWDPID()` (line 1344) queries SCM: `OpenService("WinDefend")` -> `QueryServiceStatusEx`
   - If caller is Defender: signals event, creates oplock on .lock file, responds with placeholder
   - Defender tries to hydrate/access .lock file, hits oplock, freezes

5. VSS remains accessible while Defender is frozen

**This is the most novel technique in the exploit.** Cloud Files API is designed for
cloud storage sync engines (OneDrive, Dropbox). Using it for process identification
and selective freezing is creative and currently undermonitored.

### Stage 5: Junction + Symlink Race (lines 3068-3302)

**Objective:** Redirect Defender's privileged file read from update files to the SAM database.

1. Update files written to `%TEMP%\<GUID>\` on disk
2. RPC call: `Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, updatepath, &errstat)`
   - UUID: `c503f532-443a-4c69-8300-ccd1fbdb3839`
   - Endpoint: `ncalrpc:IMpService77BDAF73-B396-481F-9042-AD358843EC24`
3. Defender creates new directory under `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\`
4. Oplock on `mpasbase.vdm` — Defender pauses when reading this file

**While Defender is paused:**

5. Rename `%TEMP%\<GUID>` -> `%TEMP%\<GUID>.foo`
6. `NtCreateFile` recreates `%TEMP%\<GUID>` as empty directory with `FILE_DELETE_ON_CLOSE`
7. `FSCTL_SET_REPARSE_POINT` sets junction: `%TEMP%\<GUID>` -> `\BaseNamedObjects\Restricted`
8. `NtCreateSymbolicLinkObject`: `\BaseNamedObjects\Restricted\mpasbase.vdm` -> `\Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM`

**Path resolution when oplock releases:**
```
%TEMP%\<GUID>\mpasbase.vdm
  -> [NTFS junction] -> \BaseNamedObjects\Restricted\mpasbase.vdm
    -> [Object Manager symlink] -> \Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM
```

Defender (running as SYSTEM) reads the SAM file thinking it's a signature database,
copies it to Definition Updates directory. PoC reads it from there.

**Key insight:** `\BaseNamedObjects\Restricted` is writable by standard users. This is the
pivot point between the NTFS namespace and the kernel object manager namespace.

### Stage 6: SAM Hash Extraction (lines 1785-2820)

**Boot key derivation** (`GetLSASecretKey`, line 1785):
- Reads class names from: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD, Skew1, GBG, Data}`
- Concatenates and permutes via fixed index table:
  `{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}`

**SAM decryption chain:**
```
OROpenHive(sam_path) -> offline SAM access
ORGetValue("SAM\Domains\Account", "F") -> encrypted password encryption key (PEK)
UnprotectPasswordEncryptionKey(samkey, bootkey) -> AES-128-CBC decrypt PEK
  For each user RID:
    ORGetValue("SAM\Domains\Account\Users\<RID>", "V") -> user record
    UnprotectNTHash(PEK, encrypted_hash, RID):
      UnprotectPasswordHashAES() -> AES-128-CBC layer
      UnproctectPasswordHashDES() -> DES-ECB with RID-derived keys
      -> plaintext 16-byte NTLM hash
```

**Credential abuse** (`DoSpawnShellAsAllUsers`, line 2481):
For each user (skipping current user, null hashes, WDAGUtilityAccount):
1. `SamiChangePasswordUser(huser, false, oldLM, newLM, true, oldNTLM, newNTLM)`
   - oldNTLM = extracted hash (no plaintext needed)
   - newNTLM = hash of `$PWNed666!!!WDFAIL`
2. `LogonUserEx(username, NULL, L"$PWNed666!!!WDFAIL", LOGON32_LOGON_INTERACTIVE, ...)`
3. Check `TokenElevationType` — if `TokenElevationTypeLimited`, query `TokenLinkedToken`
4. Check admin: `CheckTokenMembership` for `WinBuiltinAdministratorsSid`
5. If admin: impersonate, set medium integrity (`S-1-16-8192`), create temp service (see Stage 7)
6. `CreateProcessWithLogonW` -> `conhost.exe` in new console
7. Restore password: `SamiChangePasswordUser` with original NTLM hash

### Stage 7: SYSTEM Escalation (lines 2738-2876)

When an admin user is found:
1. `LogonUserEx` with `LOGON32_LOGON_BATCH` to get a batch logon token
2. Set token integrity to Medium (`S-1-16-8192`) via `SetTokenInformation(TokenIntegrityLevel)`
3. `ImpersonateLoggedOnUser` with this medium-integrity admin token
4. `OpenSCManager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)`
5. `CreateService` with:
   - Name: random GUID
   - BinPath: `"<FunnyApp.exe path> <session_id>"`
   - Type: `SERVICE_WIN32_OWN_PROCESS`
   - Start: `SERVICE_DEMAND_START`
6. `StartService` -> binary runs as SYSTEM (handled by Stage 0 dispatch)
7. `DeleteService` immediately after start

The SYSTEM instance calls `LaunchConsoleInSessionId` (line 2843):
- Duplicates SYSTEM token
- Sets session ID to user's desktop session
- `CreateProcessAsUser` -> `conhost.exe` as SYSTEM in user's session

---

## 4. Bug Inventory and Fixes

| # | Location | Bug | Impact | Fix |
|---|---|---|---|---|
| 1 | Line 688 | `hint` nulled instead of `hint2` after close | `hint2` double-close in cleanup | Changed to `hint2 = NULL` |
| 2 | Line 3380 | Cleanup checks `hint` twice, closes `hint2` | Wrong handle guarded | Changed to `if(hint2)` |
| 3 | Lines 3384-3385 | `UnmapViewOfFile` on malloc'd buffer | Crash in cleanup | Removed dead `UnmapViewOfFile`/`hmapping` cleanup |
| 4 | Line 2188 | `ZeroMemory(retval, size + 1)` too small | Partial zeroing (cosmetic) | Changed to `size * 2 + 1` |
| 5 | Lines 2113, 2117 | `sizeof(data)` is pointer size (8), not 7 | Correct by accident on x64 | Explicit `const int DATA_LEN = 7`, `malloc(8)` |
| 6 | Line 1294 | VSS finder infinite spin, no sleep | 100% CPU, no exit condition | Added `Sleep(50)` between retries |
| 7 | Lines 1863 | `hcryptkey`/`hprov` leaked in `UnprotectAES` | Handle leak per call | Added `CryptDestroyKey`/`CryptReleaseContext` |
| 8 | Line 2049 | `hcryptkey` leaked in `UnprotectDES` | Handle leak per call | Added `CryptDestroyKey` before `CryptReleaseContext` |

**Unfixed (won't prevent execution):**
- Memory leaks in `DoSpawnShellAsAllUsers`: PEK, samkey, pwdenclist entries, DES keys,
  intermediate decryption buffers never freed. Acceptable for single-run PoC.
- No retry logic for RPC error `0x8050A003` (engine version mismatch).

---

## 5. Reusable Exploitation Primitives

These are modular techniques that can be extracted and reused against different targets.

### Primitive 1: Oplock-Based TOCTOU Framework
**Technique:** Open file -> `FSCTL_REQUEST_BATCH_OPLOCK` -> wait for privileged process to
access -> swap filesystem underneath -> release oplock
**Reuse:** Any privileged service that predictably accesses files in user-writable locations.
Replace `RstrtMgr.dll` / `mpasbase.vdm` with target-specific files.
**Risk:** HIGH — generic pattern, continuously rediscovered against different services.

### Primitive 2: Cloud Files API for Process ID + Selective Freeze
**Technique:** Register sync root -> create placeholder -> callback provides caller PID/image ->
selectively respond or stall based on process identity
**Reuse:** Any security product that scans/enumerates directories through the filesystem.
Could freeze EDR agents during malicious activity.
**Risk:** HIGH — novel, undermonitored API surface.

### Primitive 3: Junction + Object Manager Symlink Chain
**Technique:** NTFS junction -> `\BaseNamedObjects\Restricted` -> object manager symlink -> NT path
**Reuse:** Redirect any privileged file read to any file accessible by the privileged process.
Targets beyond SAM: SYSTEM hive, SECURITY hive, NTDS.dit (on DCs), any locked file.
**Risk:** MEDIUM-HIGH — pattern is known (James Forshaw), but specific routes vary.

### Primitive 4: Unprivileged VSS Creation via AV Triggering
**Technique:** EICAR drop -> AV remediation -> VSS snapshot -> oplock freeze to keep VSS alive
**Reuse:** Any AV product that creates VSS during remediation. Replace EICAR trigger
with product-specific detection trigger.
**Risk:** MEDIUM — product-specific, but concept generalizes.

### Primitive 5: SAM Dump + SamiChangePasswordUser (Local Pass-the-Hash)
**Technique:** Given NTLM hash, change password without knowing plaintext, logon, restore.
**Reuse:** Pair with any SAM leak method. Eliminates need for offline cracking.
**Risk:** HIGH — well-known technique but detection gap exists in many environments.

### Primitive 6: Temporary Service for SYSTEM Escalation
**Technique:** CreateService (GUID name) -> StartService -> DeleteService.
**Reuse:** Standard admin->SYSTEM escalation. Interesting twist: medium-integrity token
used for SCM access.
**Risk:** MEDIUM — well-detected by most EDR, but the integrity level manipulation may
evade some heuristics.

---

## 6. Indicators of Compromise

### Network IoCs

| Indicator | Type | Notes |
|---|---|---|
| `go.microsoft.com/fwlink/?LinkID=121721&arch=x64` | URL | Legitimate Microsoft URL — context-dependent |
| User-Agent `Chrome/141.0.0.0` from non-browser process | HTTP Header | Strong indicator when correlated with process |
| TLS SNI to `go.microsoft.com` from console application | Network Metadata | Weak alone, strong with process context |

### Host IoCs — Filesystem

| Indicator | Type | Notes |
|---|---|---|
| GUID-named directories in `%TEMP%` with `.vdm` files | Filesystem | Update staging artifacts |
| `%TEMP%\<GUID>.foo` renamed directories | Filesystem | Mid-race directory swap |
| `%TEMP%\<GUID>.WDFOO` renamed files | Filesystem | Oplock pivot file |
| `%TEMP%\<GUID>\foo.exe` containing EICAR | Filesystem | Defender trigger file |
| NTFS junction from `%TEMP%` to `\BaseNamedObjects\Restricted` | Filesystem | Core exploit pivot |
| GUID-named file in `%TEMP%` with SAM database content | Filesystem | Leaked SAM file |

### Host IoCs — Process/Behavioral

| Indicator | Type | Notes |
|---|---|---|
| `samlib.dll` loaded by non-LSASS process | DLL Load | SamiChangePasswordUser access |
| Rapid 4723->4624->4723 sequence for same user (<30s) | Event Sequence | Password change-logon-restore cycle |
| `CfRegisterSyncRoot` by non-cloud-storage process | API Call | Cloud Files API abuse |
| Service with GUID name, created and deleted within seconds | Service Event | SYSTEM escalation |
| `conhost.exe` spawned by non-shell process | Process Tree | Shell spawning |
| `FSCTL_REQUEST_BATCH_OPLOCK` on `RstrtMgr.dll` by non-system process | Kernel File Op | Race condition setup |
| Registry reads to `Lsa\{JD,Skew1,GBG,Data}` by non-LSASS process | Registry | Boot key extraction |
| RPC to `IMpService` endpoint from non-Defender process | RPC | Defender update manipulation |
| Object manager symlink in `\BaseNamedObjects\Restricted` targeting VSS path | Kernel Object | File redirection |

### Host IoCs — Strings (for YARA/memory scanning)

| String | Encoding | Context |
|---|---|---|
| `IHATEMICROSOFT` | Wide/ASCII | Cloud Files provider name (easily changed) |
| `$PWNed666!!!WDFAIL` | Wide/ASCII | Temporary password (easily changed) |
| `c503f532-443a-4c69-8300-ccd1fbdb3839` | Wide/ASCII | WD RPC UUID (structural, unlikely to change) |
| `IMpService77BDAF73-B396-481F-9042-AD358843EC24` | Wide/ASCII | WD ALPC endpoint (structural) |
| Reversed EICAR string | ASCII | AV evasion for EICAR storage |
| `SAM\Domains\Account` | Wide | SAM hive path (structural) |
| `SamiChangePasswordUser` | ASCII | Undocumented API import (structural) |

---

## 7. Detection Rules

### Sigma Rules (7 rules)

| Rule | File | Detects | Severity |
|---|---|---|---|
| samlib.dll load | `bluehammer_samlib_load.yml` | Non-LSASS loading samlib.dll | High |
| Rapid password cycle | `bluehammer_rapid_password_change.yml` | Change->logon->restore pattern | Critical |
| Junction to BaseNamedObjects | `bluehammer_junction_basenamed.yml` | NTFS reparse to kernel namespace | Critical |
| GUID service creation | `bluehammer_temp_service_creation.yml` | Temp service for SYSTEM escalation | High |
| RstrtMgr.dll oplock | `bluehammer_oplock_rstrtmgr.yml` | Exclusive handle on RstrtMgr.dll | Medium |
| Cloud Files API abuse | `bluehammer_cloudfiles_abuse.yml` | CldApi.dll load by non-provider | High |
| LSA boot key access | `bluehammer_lsa_bootkey_access.yml` | Boot key registry reads | Critical |
| Defender RPC call | `bluehammer_defender_rpc_call.yml` | Non-Defender RPC to IMpService | High |

### YARA Rules (4 rules)

| Rule | Detects | Scope |
|---|---|---|
| `BlueHammer_Exact` | Exact PoC binary via string combinations | Static scan |
| `BlueHammer_Variant_DefenderOplock` | Variants reusing Defender oplock+junction chain | Variant detection |
| `BlueHammer_Variant_SAMDump_SamiChange` | Variants reusing SAM dump + SamiChangePasswordUser | Variant detection |
| `BlueHammer_Variant_CloudFilesFreeze` | Variants reusing Cloud Files process freeze | Variant detection |

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | BlueHammer Stage |
|---|---|---|---|
| Reconnaissance | — | — | — |
| Resource Development | — | — | — |
| Initial Access | — | — | Not applicable (requires local execution) |
| Execution | T1569 | .002 Service Execution | Stage 7: Temp service start |
| Persistence | — | — | None (single-run) |
| Privilege Escalation | T1068 | — Exploitation for Privilege Escalation | Stages 3-5: Oplock+junction chain |
| Privilege Escalation | T1543 | .003 Windows Service | Stage 7: Service creation for SYSTEM |
| Defense Evasion | T1562 | .001 Disable or Modify Tools | Stage 4: Freezing Defender via Cloud Files |
| Defense Evasion | T1574 | .005 Executable Installer File Permissions Abuse | Stage 5: Junction+symlink redirect |
| Credential Access | T1003 | .002 SAM | Stage 6: SAM extraction via VSS |
| Credential Access | T1552 | .002 Credentials in Registry | Stage 6: LSA boot key from registry |
| Credential Access | T1098 | — Account Manipulation | Stage 6: Password change via SamiChangePasswordUser |
| Lateral Movement | — | — | Not applicable (local only) |
| Collection | T1005 | — Data from Local System | Stage 5: SAM file exfiltration from VSS |

---

## 9. Lab Execution Guidance

### Prerequisites
- Windows VM (GOAD environment, latest patches)
- EDR and NDR agents active and logging
- Sysmon installed with comprehensive configuration
- All Windows event log channels enabled (Security, System, Defender Operational)
- Visual Studio 2022 with Windows SDK 10.0.26100.0 for building
- Network monitoring on the VM's interface

### Build
```
Open FunnyApp.sln in Visual Studio 2022
Select: Release | x64
Build -> Build Solution
Output: x64\Release\FunnyApp.exe
```

### Pre-Execution Checklist
1. Verify Defender real-time protection is ON
2. Check for pending Defender definition updates (may need to delay/block auto-update)
3. Ensure multiple local user accounts exist (the exploit iterates all accounts)
4. Start packet capture on VM network interface
5. Confirm Sysmon is logging (check for recent events in Sysmon Operational log)
6. Take filesystem snapshot for post-execution diff

### Execution
```
x64\Release\FunnyApp.exe
```
Run as a standard (non-admin) user. The exploit will print status messages for each stage.

### Expected Behavior
1. "Checking for windows defender signature updates..." — may wait here if no updates pending
2. "Downloading updates..." — HTTPS to Microsoft CDN
3. "Creating VSS copy..." — EICAR drop, oplock activity
4. "Waiting for callback..." — Cloud Files registration, waiting for Defender to scan
5. "WD is frozen..." — Defender paused on oplock
6. "Exploit succeeded." — SAM leaked
7. User credential dumps printed to console
8. "Shell : OK" / "SYSTEMShell : OK" — shells spawned
9. "PasswordRestore : OK" — credentials restored

### Post-Execution Analysis
1. Collect all event logs (Security, System, Sysmon, Defender Operational)
2. Export packet capture
3. Filesystem diff against pre-execution snapshot
4. Process tree capture
5. Cross-reference observed events against IoC Observation Guide
6. Validate which Sigma rules fired in SIEM
7. Run YARA rules against the binary and memory dumps

---

## 10. References

- BlueHammer PoC source code (analyzed repository)
- Microsoft Cloud Files API: https://learn.microsoft.com/en-us/windows/win32/cfapi/
- James Forshaw — Windows symlink/junction attacks: Project Zero research
- Microsoft Offline Registry Library (offreg.h)
- EICAR test standard: https://www.eicar.org/download-anti-malware-testfile/
- SAM database structure and SYSKEY derivation: Moyix blog series
- MITRE ATT&CK: https://attack.mitre.org/

---

*This report contains information about offensive security techniques for defensive purposes only.
Distribution should be limited to authorized security and engineering personnel.*
