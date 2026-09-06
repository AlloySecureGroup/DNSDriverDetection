# DriverCanary

A single PowerShell script that inventories Windows kernel drivers, builds an explicitly reviewed path/SHA-256 allowlist, and sends a DNS Canarytoken query when ETW reports an unapproved kernel image load. The endpoint name and driver filename are encoded in the query.

**Validation status:** this package was prepared on macOS. Windows compilation, ETW delivery, and end-to-end Canarytoken receipt have **not** been executed here. Complete the Windows acceptance test below before deployment. This is a detection prototype, not a guaranteed defense against an EDR killer.

## Requirements and timing

- x64 Windows 10 or Windows 11, running native **64-bit Windows PowerShell 5.1** as administrator. This implementation deliberately excludes 32-bit Windows and ARM64.
- FullLanguage mode and permission to use `Add-Type`. Follow your organization's script-signing policy; do not disable application control or change machine-wide execution policy for this script.
- A DNS Canarytoken hostname and working recursive DNS. No Python, Sysmon, SDK, external PowerShell module, or additional monitoring driver is needed. Embedded C# compiles using the Windows-provided .NET Framework.
- Inventory enables the caller's SeDebugPrivilege to enumerate loaded drivers, including on Windows 11 24H2. It does not change account rights or grant a missing privilege. Run inventory in a dedicated PowerShell process and close it afterwards. [Microsoft: EnumDeviceDrivers](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers)

The script starts its own named system ETW session and consumes kernel image events through the native ETW/TDH APIs. It filters on x64 kernel virtual image addresses rather than filename extensions. Load opcode 10 means a new load; opcode 3 means an image reported in startup rundown. The latter is also checked and alerted, but labeled `ExistingAtTraceStart` in enrichment records. User-mode DLL loads are excluded. [Microsoft: image events](https://learn.microsoft.com/en-us/windows/win32/etw/image-load), [system trace sessions](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session)

**“Immediate” means dispatch as soon as the event is delivered and the allowlist decision is made.** ETW uses a one-second buffer flush interval; scheduling, file reads, existing work, DNS retries, and Canarytoken notification processing can add latency. There is no strict upper bound. This is not WMI polling, a service-install event trigger, or a periodic inventory comparison. [Microsoft: ETW properties and buffering](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)

## 1. Prepare a protected working directory

Extract this ZIP. Open native Windows PowerShell as administrator in the extracted folder. Use a new deployment directory, or verify an existing directory contains only your intended files before applying these ACLs:

```powershell
$dest = "$env:ProgramData\DriverCanary"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
icacls.exe $dest /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'ACL configuration failed' }
Copy-Item .\DriverCanary.ps1 "$dest\DriverCanary.ps1"
Set-Location $dest
.\DriverCanary.ps1 -Mode SelfTest
```

The SIDs identify SYSTEM and local Administrators without depending on the Windows display language. Inspect existing explicit permissions with `icacls.exe $dest`; the command above removes inherited permissions but does not remove unrelated explicit grants already present. Keep the script, inventory, allowlist, logs, and any custom data directories writable only by trusted administrators/SYSTEM.

`SelfTest` compiles the embedded code and checks Base32 test vectors and DNS length limits without sending DNS. It does **not** test ETW or load a driver.

## 2. Inventory and review

Run on a known-good endpoint, before running the Procmon test:

```powershell
.\DriverCanary.ps1 -Mode Inventory
```

This writes `inventory.json` and `inventory.csv`. An existing JSON inventory is not overwritten. To take another snapshot, supply a different `-InventoryPath`.

Inventory combines:

- Currently loaded kernel modules from `EnumDeviceDrivers`, including modules with extensions other than `.sys`.
- Registered system-driver services from `Win32_SystemDriver`, including stopped services and their state/start mode.
- `.sys` files recursively under `System32\drivers` and `System32\DriverStore\FileRepository`.
- PnP driver metadata from `Win32_PnPSignedDriver`, including INF name, provider, reported signing information, and version.

Per-file records include original/resolved path, filename, SHA-256, size, modification time, version/product/company metadata, Authenticode status/type/message, signer subject/issuer/thumbprint/expiry, timestamp signer, and any read/validation error. Service and PnP records remain separate collections in JSON; the CSV is the file review view.

This is an inventory of those observable scopes, not a forensic guarantee that every driver anywhere on disk has been found. Add custom directories with `-ScanRoot`; unregistered, unloaded files outside the scan roots are not included. A full-drive `.sys` scan is possible but expensive:

```powershell
.\DriverCanary.ps1 -Mode Inventory -InventoryPath "$dest\inventory-wide.json" -ScanRoot 'C:\','D:\'
```

Review `ScanErrors` and file `Error` fields. Inaccessible files remain unresolved evidence; they are not silently trusted. A file can change during inventory. Approval rechecks its hash, while signature and hash measurements are separate observations.

`Get-AuthenticodeSignature` checks Windows Authenticode trust and can report catalog signatures, not just embedded signatures. Its outcome depends on local trust/catalog state and certificate validation conditions. The script records its reported result; it does not implement an independent kernel signing-policy or vulnerability assessment, nor locate/export every associated `.cat` file. A valid signature does not establish that a driver is safe. [Microsoft: Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.5)

Every file starts with Boolean `"Approved": false`. Review the JSON and change **only the specific accepted rows** to `true`. Editing the CSV does not approve anything. Do not approve all signed drivers or blindly trust the current host's entire inventory.

```powershell
notepad.exe "$dest\inventory.json"
.\DriverCanary.ps1 -Mode Approve
```

`Approve` creates `approved.json` with the selected exact path/hash pairs. It refuses an empty selection, malformed hashes, changed files, or an existing output baseline. Approve all legitimate kernel modules needed for your intended configuration; otherwise startup rundown can legitimately produce alerts.

## 3. Configure and test DNS

Create a **DNS** token at [Canarytokens](https://canarytokens.org). Use the exact returned hostname, without a URL, path, or wildcard:

```powershell
$token = 'REPLACE-WITH-YOUR-REAL-DNS-TOKEN.canarytokens.com'
.\DriverCanary.ps1 -Mode TestDns -Token $token
```

This sends a **real** alert with driver name `DNS-TEST.sys`. Confirm receipt in the token's incident history. It proves the DNS path only, not driver detection.

Payloads use UTF-8 Base32 without padding, split into DNS labels, followed by Canarytokens' `G` marker and the token hostname. Decoded data resembles `id=0123456789abcdef;p=001/001;e=LAB-PC;d=PROCMON99.SYS`. The name is an example; Procmon's actual driver name varies. [Canarytokens: DNS token encoding](https://docs.canarytokens.org/guide/dns-token)

`e` is the Windows computer name, `d` the filename, and `id` a per-event correlation value. Oversized payloads are divided across queries with the same `id` and numbered `p` fields. Concatenate the content after the `p` field in part order to recover the full `e=...;d=...` text. Each query is at most 253 characters before the trailing root dot; each label is at most 63. Full paths, hashes, and signatures remain in local logs. Encoding is not encryption: names are visible to your resolvers and Canarytoken operator. Computer names may not be globally unique across domains.

Queries use the Windows configured DNS resolvers, bypass local cache information, and use a fully qualified name. Unique event IDs reduce cache reuse; the Windows resolver may itself use your configured encrypted DNS transport. The script does not select an external resolver or bypass network policy. [Microsoft: DNS query options](https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants)

A successful DNS response is not proof of notification delivery; an NXDOMAIN response can still accompany a query that reached the token service. Check incident history. Recursive DNS filtering, sinkholes, lack of connectivity, provider suppression/rate limits, or missing multipart queries can prevent complete alerts. There is no durable delivery queue or application-level retry/replay; DNS retries are controlled by Windows.

## 4. Monitor

```powershell
.\DriverCanary.ps1 -Mode Monitor -Token $token
```

Wait for `ETW active` before testing. Keep the process running. Ctrl+C stops the monitor and releases its ETW session during normal cleanup.

| Load decision | Behavior |
| --- | --- |
| Path is not approved | Queue DNS without waiting for hash/signature enrichment |
| Path is approved and current SHA-256 matches | Record the load without DNS |
| Path is approved but SHA-256 differs | Queue DNS with `HashMismatch` |
| Path resolution or hash fails | Queue DNS with `Unverifiable` |

Each unapproved load can alert, including a later reload of the same driver. There is no filename-only approval, signer-wide trust rule, or automatic learning. Allowlist changes take effect only after restarting the monitor. Preserve and review a new inventory/baseline for Windows and driver updates instead of silently expanding trust.

The native ETW callback only decodes and queues. Separate C# decision and DNS threads continue independently of PowerShell signature enrichment. Known-path hashing can delay the decision worker; a slow DNS query can delay subsequent queries in the DNS worker. Bounded queues count overflow as coverage loss. Local log persistence and health checks can lag if signature validation stalls.

Logs are daily `events-YYYYMMDD.jsonl` files under the data directory. Records include `MonitorStarted`, `Load`, `Enrichment`, `DnsDispatch`, `DnsResult`, `Health`, `MonitorFailed`, and `MonitorStopped`. Join records by `EventId`, not line order. `Load.Opcode=10` distinguishes new loads from startup rundown (`3`). `DnsDispatch.DispatchUtc - Load.EventUtc` measures the delay to the DNS API call; it does not measure receipt at Canarytokens.

Every ten seconds, when the PowerShell loop is available, the script checks ETW session loss counters, decode errors, queue drops, and worker failures. A failure is logged and terminates monitoring with an error. Arrange separate supervision/log forwarding and retention: this script does not alert externally when it is killed, rotate by size, or survive disk exhaustion.

## 5. Acceptance test: load a Sysinternals Procmon driver

Use a disposable Windows VM with a snapshot. Use a current legitimate Procmon build, not an old vulnerable driver. Leave Secure Boot, Memory Integrity, the vulnerable-driver blocklist, and other protections enabled.

1. Start with Procmon never run since boot, ideally never installed on this VM. Complete inventory and approvals **without approving Procmon**. If Procmon was previously used, close it and reboot first; closing its UI alone does not prove its driver unloaded.
2. Download and extract Process Monitor from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to `C:\Tools\ProcessMonitor`. Verify the executable signature and review its license before using `/AcceptEula` below.
3. Start DriverCanary in one elevated PowerShell window and wait for `ETW active`. Run these commands in a second elevated window:

```powershell
Get-AuthenticodeSignature 'C:\Tools\ProcessMonitor\Procmon64.exe' |
    Format-List Status,SignerCertificate

# Run after reviewing the signature and accepting the Sysinternals license.
$testStarted = [DateTime]::UtcNow
Start-Process 'C:\Tools\ProcessMonitor\Procmon64.exe' -ArgumentList '/AcceptEula','/Quiet','/Minimized'
```

Starting Procmon should load its signed kernel driver if it is not already loaded and Windows permits the load. The monitor must show a **new** load for the actual Procmon driver path. Copying the executable or registering a service is not sufficient evidence.

Inspect the log after giving enrichment time to finish:

```powershell
$records = Get-ChildItem "$env:ProgramData\DriverCanary\events-*.jsonl" |
    Get-Content | ForEach-Object { $_ | ConvertFrom-Json }
$loads = @($records | Where-Object {
    $_.Kind -eq 'Load' -and $_.Opcode -eq 10 -and
    $_.RawPath -match '(?i)procmon.*\.sys$' -and
    ([datetime]$_.ObservedUtc).ToUniversalTime() -ge $testStarted
})
if ($loads.Count -eq 0) { throw 'No NEW Procmon driver load observed: test has not passed.' }
$loads | Format-List EventId,RawPath,Path,Reason,Approved,EventUtc,ObservedUtc
$ids = @($loads | ForEach-Object { $_.EventId })
$records | Where-Object { $_.EventId -in $ids } | Format-List
```

Pass criteria: a post-test `Load` with opcode 10 and `Approved=false`; a matching `DnsDispatch`; and a received Canarytoken incident carrying this endpoint and driver name. Save actual measured timing. A manual `TestDns` incident, a rundown event, or a log entry without confirmed receipt does not pass the end-to-end test.

Stop Procmon after the test:

```powershell
& 'C:\Tools\ProcessMonitor\Procmon64.exe' /Terminate /Quiet
```

This terminates Procmon instances, so use it only in the test VM. Reboot or restore the snapshot before repeating a first-load test. Microsoft documents Procmon launch/termination commands in its [troubleshooting guide](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/troubleshoot-apps-start-failure-use-process-monitor).

For a negative control, while the legitimate Procmon driver file is still available, inventory to a new file, explicitly approve its actual path/hash along with your existing reviewed entries, and create a new baseline. Restart the monitor using that baseline and induce a fresh load after a reboot. Expect `Approved=true` and no DNS for that event, provided path and bytes are unchanged. If the file is extracted under a different path, an alert is correct under this policy. Also verify ordinary user-mode DLL loads do not generate `Load` records.

## Optional: start with Task Scheduler

After the acceptance test succeeds, use the protected deployment directory and an elevated PowerShell window:

```powershell
$scriptPath = "$env:ProgramData\DriverCanary\DriverCanary.ps1"
$token = 'REPLACE-WITH-YOUR-REAL-DNS-TOKEN.canarytokens.com'
if ($token -notmatch '^[A-Za-z0-9.-]+$') { throw 'Invalid token hostname' }
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument ('-NoProfile -NonInteractive -File "{0}" -Mode Monitor -Token "{1}"' -f $scriptPath,$token)
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'DriverCanary' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName 'DriverCanary'
```

Stop the foreground monitor first: only one instance is supported. The token appears in task arguments and is not a secret authentication credential. Task Scheduler starts after early boot; it is not a boot-start collector. Its restart policy is finite and is not tamper protection.

If the process is forcibly killed, its ETW session may remain. The script refuses to take over an existing session (StartTrace error 183). Confirm no legitimate DriverCanary process remains, then clean up **only this session** in an elevated shell:

```powershell
logman.exe query DriverCanary-KernelImages -ets
logman.exe stop DriverCanary-KernelImages -ets
```

Other StartTrace errors can indicate privilege or system-logger resource limits. Never stop another product's trace session to make room without understanding its purpose. To remove the scheduled deployment:

```powershell
Stop-ScheduledTask -TaskName 'DriverCanary'
Unregister-ScheduledTask -TaskName 'DriverCanary' -Confirm:$false
# Check for an orphaned DriverCanary-KernelImages session as above.
```

## Security and coverage limits

The detector observes normal kernel image-load telemetry after Windows has accepted a load. A malicious driver may execute and kill the monitor, suppress telemetry, or disrupt DNS before the query leaves. Administrators/SYSTEM can also change the script or baseline. This cannot guarantee it wins that race and does not block the load.

An already approved vulnerable driver can be abused without loading anything new. Manually mapped/hidden drivers, compromised kernel telemetry, loads before startup that unload before rundown, lost events, and periods when monitoring is stopped can escape observation. UMDF/user-mode drivers are outside this kernel-image detector. Boot rundown is supplementary and is not a complete historical boot audit.

Hashes and signatures describe the file read from disk after the event, not a cryptographic measurement of the mapped kernel bytes. A replacement/deletion race, aliases, alternate device mappings, or reparse points can affect results; unresolved paths alert rather than becoming trusted. Use an independent enforcement/telemetry layer for prevention and tamper-resistant evidence. The Procmon test establishes behavior on your tested Windows build, not universal driver coverage or a production latency guarantee.
