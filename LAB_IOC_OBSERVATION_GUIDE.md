# BlueHammer Lab IoC Observation Guide

Use this checklist when executing BlueHammer in your test environment.
Enable all log sources BEFORE execution. Each section maps to an exploit stage.

---

## Pre-Execution: Log Sources to Enable

### Windows Event Logs
- **Security** (4688, 4720, 4723, 4724, 4738, 7045): Process creation, account changes, service install
- **System** (7045, 7034, 7035, 7036): Service creation/start/stop/delete
- **Microsoft-Windows-Windows Defender/Operational**: All Defender events (scans, updates, detections)
- **Microsoft-Windows-Sysmon/Operational**: If Sysmon installed (strongly recommended)

### Sysmon Configuration (Recommended)
Ensure these event IDs are captured:
- **Event 1** (Process Create): All process creation with command lines
- **Event 3** (Network Connection): Outbound HTTPS
- **Event 7** (Image Loaded): DLL loads, especially samlib.dll
- **Event 10** (Process Access): Cross-process handle operations
- **Event 11** (File Create): File creation in %TEMP% and Defender directories
- **Event 12/13/14** (Registry): HKLM\SYSTEM\CurrentControlSet\Control\Lsa subkey access
- **Event 15** (FileCreateStreamHash): Alternate data streams

### ETW Providers (if your EDR captures these)
- `Microsoft-Windows-Kernel-File` (oplock operations, junction creation)
- `Microsoft-Windows-Kernel-Registry` (SAM/LSA registry access)
- `Microsoft-Windows-Security-Auditing` (logon events, privilege use)
- `Microsoft-Windows-CloudFiles-Core` (Cloud Files API sync root registration)
- `Microsoft-Windows-RPC` (ALPC calls to WinDefend)

### Network (NDR)
- DNS resolution logging
- Full HTTPS metadata (SNI, certificate info)
- Internal RPC/ALPC traffic if captured

---

## Stage 1: Update Check (Lines 3036-3044)

### What Happens
PoC polls Windows Update Agent COM API every 30 seconds for Defender definition updates.

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| Sysmon Event 1 | Process creation | `FunnyApp.exe` launches — capture full command line and parent process |
| COM/WMI trace | CoCreateInstance | `Microsoft.Update.Session` CLSID instantiation from non-standard process |

### IoCs
- Non-Windows-Update process querying `IUpdateSearcher::Search`
- Repeated COM object creation from a console application

---

## Stage 2: Update Download (Lines 599-783)

### What Happens
Downloads Defender update stub from Microsoft CDN via WinINet API. User-Agent: `Chrome/141.0.0.0`

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| Sysmon Event 3 | Network connection | Outbound HTTPS to `go.microsoft.com` (resolves to Microsoft CDN) |
| NDR | TLS handshake | SNI: `go.microsoft.com`, then redirect to `definitionupdates.microsoft.com` or similar CDN |
| Proxy/Firewall | HTTP metadata | User-Agent `Chrome/141.0.0.0` from a non-browser process |
| Sysmon Event 7 | Image load | `wininet.dll` loaded by `FunnyApp.exe` |

### IoCs
- **Chrome User-Agent from non-Chrome process** — this is the strongest network-level IoC
- WinINet API usage from a console application downloading a PE file
- Large download (~100MB+) from Microsoft CDN by non-update process

---

## Stage 3: EICAR Drop & VSS Trigger (Lines 1593-1753)

### What Happens
1. Creates `%TEMP%\<GUID>\foo.exe` containing the EICAR test string
2. Opens `%windir%\System32\RstrtMgr.dll` with exclusive access + batch oplock
3. Re-opens `foo.exe` to trigger Defender real-time scan
4. Defender detects EICAR, tries to remediate, loads RstrtMgr.dll, hits oplock, freezes
5. Defender's freeze triggers VSS snapshot creation

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| Sysmon Event 11 | File create | `%TEMP%\<GUID>\foo.exe` created |
| Defender Operational | 1116 (Detection) | EICAR test file detected as `Virus:DOS/EICAR_Test_File` |
| Defender Operational | 1117 (Action) | Remediation action on EICAR file |
| Sysmon Event 11 | File create | Temporary directory creation in %TEMP% with GUID name |
| Kernel-File ETW | Oplock request | `FSCTL_REQUEST_BATCH_OPLOCK` on `RstrtMgr.dll` |
| Security 4688 | Process create | Note: no new process is created for VSS — Defender does it internally |
| System VSS | VSS event | New shadow copy volume created |

### IoCs
- **Batch oplock on `RstrtMgr.dll`** from a non-system process
- EICAR file creation immediately followed by oplock activity
- GUID-named directories in %TEMP% with .exe files

---

## Stage 4: Cloud Files API Abuse — Defender Process Freeze (Lines 1455-1590)

### What Happens
1. Registers a Cloud Files sync root in the PoC's directory
2. Provider name: `IHATEMICROSOFT`, version `1.0`
3. Creates placeholder `.lock` file
4. When Defender enumerates the directory, callback identifies Defender PID
5. Callback creates oplock on lock file, then responds
6. Defender hits oplock on lock file and freezes, keeping VSS alive

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| CloudFiles-Core ETW | Sync root registration | Provider `IHATEMICROSOFT` registered |
| CloudFiles-Core ETW | Connection | `CfConnectSyncRoot` with `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO` |
| CloudFiles-Core ETW | Callback | `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS` triggered by MsMpEng.exe |
| Sysmon Event 11 | File create | `.lock` file with GUID name in PoC directory |
| Kernel-File ETW | Oplock request | Second `FSCTL_REQUEST_BATCH_OPLOCK` on the .lock file |
| Sysmon Event 10 | Process access | PoC queries Defender service PID via SCM |

### IoCs
- **Cloud Files sync root registration by non-OneDrive/non-cloud-storage process**
- **Provider name `IHATEMICROSOFT`** (trivially changeable but default in this PoC)
- `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO` — process is identifying who accesses its files
- Placeholder file creation followed by oplock from same process
- `OpenService` on `WinDefend` + `QueryServiceStatusEx` from console app

---

## Stage 5: RPC Update Trigger + Oplock + Junction + Symlink Race (Lines 3068-3302)

### What Happens
1. Writes extracted update files to `%TEMP%\<GUID>\`
2. Calls `Proc42_ServerMpUpdateEngineSignature` via ALPC RPC to Defender
3. Defender creates new directory under `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\`
4. PoC oplocks `mpasbase.vdm` in the update directory
5. When Defender reads the VDM, oplock fires
6. PoC renames update dir to `<GUID>.foo`, recreates it as NTFS junction to `\BaseNamedObjects\Restricted`
7. Creates object manager symlink: `\BaseNamedObjects\Restricted\mpasbase.vdm` -> `\Device\HarddiskVolumeShadowCopyN\Windows\System32\Config\SAM`
8. Oplock releases, Defender follows junction+symlink chain, reads SAM as SYSTEM, copies it to Definition Updates dir
9. PoC reads SAM from Definition Updates directory

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| Sysmon Event 11 | File create | Multiple `.vdm` files created in `%TEMP%\<GUID>\` |
| RPC ETW | ALPC call | RPC to endpoint `IMpService77BDAF73-B396-481F-9042-AD358843EC24` UUID `c503f532-443a-4c69-8300-ccd1fbdb3839` |
| Sysmon Event 11 | File create | New directory under `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\` |
| Kernel-File ETW | Oplock | `FSCTL_REQUEST_BATCH_OPLOCK` on `mpasbase.vdm` |
| Sysmon Event 11 | Directory rename | `%TEMP%\<GUID>` renamed to `%TEMP%\<GUID>.foo` |
| Kernel-File ETW | Reparse point | `FSCTL_SET_REPARSE_POINT` (junction) on recreated `%TEMP%\<GUID>` |
| Kernel-File ETW | Junction target | `\BaseNamedObjects\Restricted` |
| Object Manager ETW | Symlink create | `\BaseNamedObjects\Restricted\mpasbase.vdm` -> `\Device\HarddiskVolumeShadowCopyN\...\SAM` |
| Security 4663 | Object access | File read on `SAM` hive via VSS path (by MsMpEng.exe / SYSTEM) |
| Sysmon Event 11 | File create | `mpasbase.vdm` appears in Definition Updates dir (actually SAM content) |

### IoCs
- **NTFS junction from %TEMP% pointing to `\BaseNamedObjects\Restricted`**
- **Object manager symlink in `\BaseNamedObjects\Restricted` pointing to VSS SAM path**
- RPC call to Defender update endpoint from non-Windows-Update process
- Directory rename + recreate + reparse point set in rapid succession
- `MsMpEng.exe` reading from `\Device\HarddiskVolumeShadowCopy*\Windows\System32\Config\SAM`
- Non-Defender process reading `mpasbase.vdm` from Definition Updates directory

---

## Stage 6: SAM Dump + Credential Theft (Lines 2481-2820)

### What Happens
1. Opens leaked SAM file with offline registry API (offreg.dll)
2. Reads LSA boot key from live registry (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data})
3. Decrypts password encryption key, then per-user NTLM hashes
4. For each user: changes password via SamiChangePasswordUser -> logs in -> spawns conhost.exe -> restores original password

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| Sysmon Event 12/13 | Registry access | Read access to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD`, `Skew1`, `GBG`, `Data` class names |
| Sysmon Event 7 | Image load | `samlib.dll` loaded by `FunnyApp.exe` |
| Security 4723 | Password change attempt | User password changed (multiple users in rapid succession) |
| Security 4724 | Password reset | Admin-initiated password reset |
| Security 4625/4624 | Logon attempt/success | `LogonUserEx` calls — LogonType 2 (Interactive) and 4 (Batch) |
| Security 4688 | Process creation | `conhost.exe` spawned by `FunnyApp.exe` (or via `CreateProcessWithLogonW`) |
| Security 4648 | Explicit credential logon | Logon using explicitly provided credentials |
| Sysmon Event 1 | Process create | `conhost.exe` with unusual parent process |

### IoCs
- **`samlib.dll` loaded by non-LSASS, non-system process**
- **Rapid password change -> logon -> password change sequence** for same account (< 5 seconds)
- **Multiple user password changes in rapid succession** from single process
- Boot key registry reads (`Lsa\JD`, `Lsa\Skew1`, `Lsa\GBG`, `Lsa\Data`) from non-LSASS process
- `conhost.exe` spawned via `CreateProcessWithLogonW` from console application
- `LogonUserEx` from non-winlogon process

---

## Stage 7: SYSTEM Escalation via Service (Lines 2738-2776)

### What Happens
1. If admin user found: impersonates admin, sets medium integrity on token
2. Creates temporary Windows service pointing to `FunnyApp.exe <sessionid>`
3. Starts service (runs as SYSTEM)
4. SYSTEM instance spawns `conhost.exe` in user's session via `CreateProcessAsUser`
5. Service immediately deleted

### Expected Logs
| Log Source | Event | Detail |
|---|---|---|
| Security 4648 | Explicit credential logon | Impersonation logon (LogonType 4 — Batch) |
| System 7045 | Service installed | New service with GUID name, binary path = `FunnyApp.exe <number>` |
| Security 4697 | Service installed | Same as above, in Security log |
| System 7036 | Service state change | Service entered running state |
| Sysmon Event 1 | Process create | `FunnyApp.exe` spawned as SYSTEM by `services.exe` |
| Security 4688 | Process create | `conhost.exe` created by SYSTEM-level `FunnyApp.exe` |
| System 7036 | Service state change | Service stopped |
| System 7045/SCM | Service deleted | GUID-named service removed immediately after start |

### IoCs
- **Service created with GUID name and immediately deleted after start**
- Service binary path is `FunnyApp.exe` with numeric argument (session ID)
- `services.exe` spawning `FunnyApp.exe` as SYSTEM
- `CreateProcessAsUser` launching `conhost.exe` with cross-session token manipulation
- Token integrity level explicitly set to Medium (`S-1-16-8192`) before SCM access

---

## Post-Execution Artifacts to Collect

### Filesystem
- [ ] `%TEMP%\<GUID>` directories (may be cleaned up)
- [ ] `%TEMP%\<GUID>.foo` renamed directories
- [ ] `%TEMP%\<GUID>.WDFOO` renamed files
- [ ] Files in `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\` — check if any `mpasbase.vdm` contains SAM data
- [ ] Leaked SAM file in %TEMP% (GUID-named, no extension)

### Registry
- [ ] Check for residual service entries (should be deleted but check)
- [ ] Cloud Files sync root registration residue

### Process Tree
- [ ] Capture full process tree showing FunnyApp.exe -> conhost.exe relationships
- [ ] Note any SYSTEM-level FunnyApp.exe instances (from service)

### Network
- [ ] DNS queries to `go.microsoft.com` and CDN endpoints
- [ ] TLS session metadata (SNI, JA3/JA4 hash of FunnyApp.exe)
