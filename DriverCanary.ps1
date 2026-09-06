#requires -Version 5.1
<#
.SYNOPSIS
Inventories kernel driver files and alerts on unapproved kernel image loads via DNS.
.DESCRIPTION
One-file, inbox-only Windows implementation. Embedded C# uses ETW, TDH and DNS APIs;
PowerShell performs inventory and Authenticode enrichment. No Python, Sysmon, SDK,
NuGet package, vulnerable driver, or third-party monitoring service is required.
Targets x64 Windows 10/11 and ARM64 Windows 11 (including Parallels guests).
Requires 64-bit Windows PowerShell 5.1, elevation, and FullLanguage mode.
See README.md for coverage, baseline review, deployment and a Procmon load test.
.PARAMETER Mode
Inventory writes an unapproved candidate inventory. Approve creates a separate
allowlist from rows explicitly marked Approved=true. Monitor watches live loads.
TestDns sends a REAL test alert. SelfTest checks encoding without network access.
.PARAMETER Token
Exact hostname of a DNS Canarytoken, without URL, path, wildcard, or custom prefix.
.PARAMETER ScanRoot
Additional directories to recursively scan for .sys files during Inventory.
.EXAMPLE
.\DriverCanary.ps1 -Mode Inventory
.EXAMPLE
.\DriverCanary.ps1 -Mode Monitor -Token 'YOUR-TOKEN.canarytokens.com'
#>
[CmdletBinding()]
param(
    [ValidateSet('Inventory','Approve','Monitor','TestDns','SelfTest')]
    [string]$Mode = 'Inventory',
    [string]$DataDirectory = "$env:ProgramData\DriverCanary",
    [string]$InventoryPath,
    [string]$BaselinePath,
    [string]$Token,
    [string[]]$ScanRoot = @(),
    [string]$TestDriverName = 'DNS-TEST.sys'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'DriverCanary requires Windows. ETW driver monitoring cannot run on this operating system.'
}
if (-not [Environment]::Is64BitProcess) {
    if ([Environment]::Is64BitOperatingSystem) {
        throw "This is a 32-bit PowerShell process. From this shell, open native PowerShell with: Start-Process -FilePath `"`$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe`" -Verb RunAs . Then run this script in the new window with the same parameters."
    }
    throw '32-bit Windows is unsupported. Use x64 Windows 10/11 or ARM64 Windows 11.'
}
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'FullLanguage is required for Add-Type; do not weaken organizational policy to run this.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run Windows PowerShell as administrator.' }
if (-not $InventoryPath) { $InventoryPath = Join-Path $DataDirectory 'inventory.json' }
if (-not $BaselinePath) { $BaselinePath = Join-Path $DataDirectory 'approved.json' }
[IO.Directory]::CreateDirectory($DataDirectory) | Out-Null

# Windows x64 and ARM64 share these 64-bit ETW layouts. Never run via SysWOW64.
# Use a fresh PowerShell window when upgrading: Add-Type definitions cannot be replaced.
if ('DriverCanary.Native' -as [type]) {
    if (-not [DriverCanary.Native].GetMethod('PlatformInfo')) {
        throw 'An older DriverCanary version is already loaded. Open a new elevated PowerShell window and run this updated script there.'
    }
}
if (-not ('DriverCanary.Native' -as [type])) {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DriverCanary {
    public sealed class Notice {
        public string Kind, EventId, RawPath, Path, SHA256, Reason, Detail, Query;
        public DateTime EventUtc, ObservedUtc, DispatchUtc;
        public uint ProcessId;
        public byte Opcode;
        public bool Approved;
    }
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] struct SystemInfo {
            public ushort Architecture, Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress, MaximumApplicationAddress;
            public UIntPtr ActiveProcessorMask;
            public uint NumberOfProcessors, ProcessorType, AllocationGranularity;
            public ushort ProcessorLevel, ProcessorRevision;
        }
        [DllImport("kernel32.dll",SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsWow64Process2(IntPtr process,out ushort processMachine,out ushort nativeMachine);
        [DllImport("kernel32.dll")] static extern void GetSystemInfo(out SystemInfo info);
        static string MachineName(ushort machine) {
            switch(machine) {
                case 0: return "Native";
                case 0x8664: return "X64";
                case 0xAA64: return "ARM64";
                case 0xA641: return "ARM64EC";
                case 0x14c: return "X86";
                default: return "0x"+machine.ToString("X4");
            }
        }
        public static string PlatformInfo() {
            if(IntPtr.Size!=8) throw new PlatformNotSupportedException("64-bit PowerShell is required");
            ushort processMachine,nativeMachine;
            try {
                if(!IsWow64Process2(GetCurrentProcess(),out processMachine,out nativeMachine))
                    throw new IOException("IsWow64Process2 failed: "+Marshal.GetLastWin32Error());
            } catch(EntryPointNotFoundException) {
                throw new PlatformNotSupportedException("Windows 10 version 1709 or later, or Windows 11, is required");
            }
            if(nativeMachine!=0x8664 && nativeMachine!=0xAA64)
                throw new PlatformNotSupportedException("Unsupported Windows architecture: "+MachineName(nativeMachine));
            if(processMachine!=0 && processMachine!=0x8664 && processMachine!=0xAA64 && processMachine!=0xA641)
                throw new PlatformNotSupportedException("Unsupported PowerShell architecture: "+MachineName(processMachine));
            return "Version=2.0; NativeOS="+MachineName(nativeMachine)+"; Process="+
                MachineName(processMachine==0?nativeMachine:processMachine)+"; WOWMachine="+
                MachineName(processMachine)+"; PointerBytes="+IntPtr.Size;
        }
        public static ulong MaximumUserAddress() {
            SystemInfo info; GetSystemInfo(out info);
            ulong maximum=unchecked((ulong)info.MaximumApplicationAddress.ToInt64());
            if(maximum<0xFFFFFFFFUL || maximum>=0x8000000000000000UL)
                throw new PlatformNotSupportedException("Unexpected 64-bit maximum application address: "+maximum.ToString("X16"));
            return maximum;
        }
        public static bool IsKernelImageAddress(ulong address,ulong maximumUserAddress) {
            // Classify valid ETW image bases using the OS-reported user-space limit.
            return address>maximumUserAddress;
        }
        [StructLayout(LayoutKind.Sequential)] struct Privilege {
            public uint Count; public uint LuidLow; public int LuidHigh; public uint Attributes;
        }
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        static extern bool LookupPrivilegeValue(string system,string name,out long luid);
        [DllImport("advapi32.dll",SetLastError=true)]
        static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege state,uint length,IntPtr previous,IntPtr needed);
        [DllImport("psapi.dll",SetLastError=true)]
        static extern bool EnumDeviceDrivers([Out] IntPtr[] addresses,uint bytes,out uint needed);
        [DllImport("psapi.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        static extern uint GetDeviceDriverFileName(IntPtr address,StringBuilder name,uint size);
        public static string[] LoadedDriverPaths() {
            // Windows 11 24H2 needs enabled SeDebugPrivilege for non-NULL addresses.
            IntPtr access;
            if(!OpenProcessToken(GetCurrentProcess(),0x20|0x8,out access)) throw new IOException("OpenProcessToken failed");
            try {
                long luid;
                if(!LookupPrivilegeValue(null,"SeDebugPrivilege",out luid)) throw new IOException("LookupPrivilegeValue failed");
                Privilege p=new Privilege {Count=1,LuidLow=(uint)luid,LuidHigh=(int)(luid>>32),Attributes=2};
                if(!AdjustTokenPrivileges(access,false,ref p,0,IntPtr.Zero,IntPtr.Zero) || Marshal.GetLastWin32Error()!=0)
                    throw new IOException("Cannot enable SeDebugPrivilege for loaded-driver inventory");
            } finally { CloseHandle(access); }
            IntPtr[] addresses=new IntPtr[1024]; uint needed;
            for(;;) {
                if(!EnumDeviceDrivers(addresses,(uint)(addresses.Length*IntPtr.Size),out needed))
                    throw new IOException("EnumDeviceDrivers failed: "+Marshal.GetLastWin32Error());
                if(needed<=addresses.Length*IntPtr.Size) break;
                addresses=new IntPtr[needed/IntPtr.Size+256];
            }
            List<string> paths=new List<string>();
            for(int i=0;i<needed/IntPtr.Size;i++) {
                if(addresses[i]==IntPtr.Zero) throw new IOException("Loaded-driver enumeration returned NULL addresses");
                StringBuilder b=new StringBuilder(32768);
                if(GetDeviceDriverFileName(addresses[i],b,(uint)b.Capacity)==0)
                    throw new IOException("GetDeviceDriverFileName failed; a driver may have unloaded, retry inventory");
                paths.Add(b.ToString());
            }
            return paths.ToArray();
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint QueryDosDevice(string name, StringBuilder target, int length);
        [DllImport("dnsapi.dll", CharSet=CharSet.Unicode, EntryPoint="DnsQuery_W")]
        static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra,
            out IntPtr records, IntPtr reserved);
        [DllImport("dnsapi.dll")] static extern void DnsRecordListFree(IntPtr records, int freeType);
        public static string Normalize(string input) {
            if (String.IsNullOrWhiteSpace(input)) throw new ArgumentException("Empty driver path");
            string p = Environment.ExpandEnvironmentVariables(input.Trim());
            if (p.StartsWith("\"")) {
                int end = p.IndexOf('"', 1);
                if (end < 0) throw new ArgumentException("Unmatched quote in driver path");
                p = p.Substring(1, end-1);
            }
            if (p.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)) p = p.Substring(4);
            if (p.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) p = p.Substring(4);
            if (p.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p.Substring(4);
            string win = Environment.GetEnvironmentVariable("SystemRoot");
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = win + p.Substring(11);
            else if (p.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) p = win + @"\" + p;
            if (p.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) {
                foreach (string d in Environment.GetLogicalDrives()) {
                    StringBuilder b = new StringBuilder(32768);
                    if (QueryDosDevice(d.Substring(0,2), b, b.Capacity) == 0) continue;
                    string dev = b.ToString();
                    if (p.StartsWith(dev + @"\", StringComparison.OrdinalIgnoreCase)) {
                        p = d.Substring(0,2) + p.Substring(dev.Length); break;
                    }
                }
            }
            if (p.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                throw new IOException("No DOS mapping for " + p);
            if (!Path.IsPathRooted(p) || (p.StartsWith(@"\") && !p.StartsWith(@"\\")))
                throw new IOException("Unresolved driver path: " + p);
            return Path.GetFullPath(p);
        }
        public static string Hash(string path) {
            // Holding a read handle denies concurrent writes/deletes during this hash.
            using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 h = SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "");
        }
        public static string Base32(byte[] data) {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            StringBuilder b = new StringBuilder(); int bits=0, value=0;
            foreach (byte x in data) {
                value=(value<<8)|x; bits+=8;
                while (bits>=5) { bits-=5; b.Append(alphabet[(value>>bits)&31]); }
                value &= (1<<bits)-1;
            }
            if (bits>0) b.Append(alphabet[(value<<(5-bits))&31]);
            return b.ToString();
        }
        public static string CheckToken(string token) {
            if (String.IsNullOrWhiteSpace(token)) throw new ArgumentException("A DNS token hostname is required");
            token=token.Trim().TrimEnd('.').ToLowerInvariant();
            if (!token.Contains(".") || token.Length>180) throw new ArgumentException("Invalid/overlong token hostname");
            foreach (string label in token.Split('.')) {
                if (label.Length<1 || label.Length>63 || label[0]=='-' || label[label.Length-1]=='-')
                    throw new ArgumentException("Invalid token label");
                foreach (char c in label) if (!(c>='a'&&c<='z') && !(c>='0'&&c<='9') && c!='-')
                    throw new ArgumentException("Supply only the DNS token hostname");
            }
            return token;
        }
        static string EncodeQuery(string payload, string token, int marker) {
            string b=Base32(Encoding.UTF8.GetBytes(payload));
            List<string> labels=new List<string>();
            for(int i=0;i<b.Length;i+=63) labels.Add(b.Substring(i,Math.Min(63,b.Length-i)));
            return String.Join(".", labels.ToArray()) + ".G" + marker.ToString("00") + "." + token;
        }
        public static string[] Queries(string endpoint, string driver, string id, string token) {
            token=CheckToken(token);
            // The event ID makes names unique, bypassing positive/negative recursive caches.
            string body="e="+endpoint+";d="+driver;
            List<string> parts=new List<string>(); string part="";
            foreach (var unit in TextUnits(body)) {
                string test="id="+id+";p=999/999;"+part+unit;
                if (EncodeQuery(test,token,10).Length>253) {
                    if(part.Length==0) throw new ArgumentException("Token leaves no payload space");
                    parts.Add(part); part=unit;
                } else part+=unit;
            }
            if(part.Length>0) parts.Add(part);
            if(parts.Count>999) throw new ArgumentException("Payload too large");
            List<string> queries=new List<string>();
            for(int i=0;i<parts.Count;i++) {
                string payload="id="+id+";p="+(i+1).ToString("000")+"/"+parts.Count.ToString("000")+";"+parts[i];
                string q=EncodeQuery(payload,token,10+(i%90));
                if(q.Length>253) throw new ArgumentException("DNS length overflow");
                queries.Add(q);
            }
            return queries.ToArray();
        }
        static IEnumerable<string> TextUnits(string s) {
            for(int i=0;i<s.Length;i++) {
                if(Char.IsHighSurrogate(s[i]) && i+1<s.Length && Char.IsLowSurrogate(s[i+1]))
                    yield return s.Substring(i++,2);
                else yield return s.Substring(i,1);
            }
        }
        public static int SendQuery(string query) {
            IntPtr result=IntPtr.Zero;
            // BYPASS_CACHE | TREAT_AS_FQDN | WIRE_ONLY. Uses configured Windows resolvers.
            try { return DnsQuery(query+".",1,0x8|0x1000|0x100,IntPtr.Zero,out result,IntPtr.Zero); }
            finally { if(result!=IntPtr.Zero) DnsRecordListFree(result,1); }
        }
    }
    public sealed class Monitor : IDisposable {
        public const string SessionName="DriverCanary-KernelImages";
        // EVENT_TRACE_PROPERTIES and EVENT_TRACE_LOGFILEW, Windows x64 / ARM64 ABI.
        [StructLayout(LayoutKind.Explicit,Size=120)] struct Properties {
            [FieldOffset(0)] public uint Size;
            [FieldOffset(24)] public Guid Guid;
            [FieldOffset(40)] public uint ClientContext;
            [FieldOffset(44)] public uint WnodeFlags;
            [FieldOffset(48)] public uint BufferSize;
            [FieldOffset(52)] public uint MinimumBuffers;
            [FieldOffset(56)] public uint MaximumBuffers;
            [FieldOffset(64)] public uint LogFileMode;
            [FieldOffset(68)] public uint FlushTimer;
            [FieldOffset(72)] public uint EnableFlags;
            [FieldOffset(88)] public uint EventsLost;
            [FieldOffset(100)] public uint RealTimeBuffersLost;
            [FieldOffset(116)] public uint LoggerNameOffset;
        }
        [StructLayout(LayoutKind.Explicit,Size=448)] struct LogFile {
            [FieldOffset(8)] public IntPtr LoggerName;
            [FieldOffset(28)] public uint ProcessTraceMode;
            [FieldOffset(424)] public IntPtr Callback;
        }
        [StructLayout(LayoutKind.Explicit,Size=112)] struct Record {
            [FieldOffset(16)] public long Timestamp;
            [FieldOffset(24)] public Guid Provider;
            [FieldOffset(45)] public byte Opcode;
        }
        [StructLayout(LayoutKind.Sequential)] struct PropertyData {
            public ulong PropertyName; public uint ArrayIndex; public uint Reserved;
        }
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void EventCallback(IntPtr record);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="StartTraceW")]
        static extern uint StartTrace(out ulong handle,string name,IntPtr properties);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="ControlTraceW")]
        static extern uint ControlTrace(ulong handle,string name,IntPtr properties,uint code);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="OpenTraceW",SetLastError=true)]
        static extern ulong OpenTrace(ref LogFile logfile);
        [DllImport("advapi32.dll")] static extern uint ProcessTrace(ulong[] handles,uint count,IntPtr start,IntPtr end);
        [DllImport("advapi32.dll")] static extern uint CloseTrace(ulong handle);
        [DllImport("tdh.dll")] static extern uint TdhGetPropertySize(IntPtr record,uint contexts,
            IntPtr context,uint count,ref PropertyData data,out uint size);
        [DllImport("tdh.dll")] static extern uint TdhGetProperty(IntPtr record,uint contexts,
            IntPtr context,uint count,ref PropertyData data,uint size,byte[] value);
        readonly BlockingCollection<Notice> incoming=new BlockingCollection<Notice>(4096);
        readonly BlockingCollection<Notice> dns=new BlockingCollection<Notice>(4096);
        readonly BlockingCollection<Notice> output=new BlockingCollection<Notice>(8192);
        readonly HashSet<string> approved=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly string token,endpoint;
        readonly ulong maximumUserAddress;
        EventCallback callback;
        Thread consumer,worker,sender;
        ulong session,trace=UInt64.MaxValue;
        IntPtr props=IntPtr.Zero, logger=IntPtr.Zero;
        volatile bool stopping;
        public volatile string FatalError;
        public long Dropped,DecodeErrors;
        public Monitor(string[] keys,string token,string endpoint) {
            ValidateInterop();
            maximumUserAddress=Native.MaximumUserAddress();
            this.token=Native.CheckToken(token); this.endpoint=endpoint;
            foreach(string k in keys) approved.Add(k);
        }
        public static string ValidateInterop() {
            if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Properties))!=120 ||
                Marshal.SizeOf(typeof(LogFile))!=448 || Marshal.SizeOf(typeof(Record))!=112 ||
                Marshal.SizeOf(typeof(PropertyData))!=16 ||
                Marshal.OffsetOf(typeof(LogFile),"Callback").ToInt32()!=424 ||
                Marshal.OffsetOf(typeof(Record),"Opcode").ToInt32()!=45)
                throw new PlatformNotSupportedException("Unexpected ETW interop layout");
            return "64-bit ETW layouts: Properties=120; LogFile=448; Record=112; PropertyData=16";
        }
        void Publish(Notice n) { if(!output.TryAdd(n)) Interlocked.Increment(ref Dropped); }
        byte[] GetProperty(IntPtr r,string name) {
            IntPtr n=Marshal.StringToHGlobalUni(name);
            try {
                PropertyData d=new PropertyData {PropertyName=(ulong)n.ToInt64(),ArrayIndex=UInt32.MaxValue};
                uint size; uint status=TdhGetPropertySize(r,0,IntPtr.Zero,1,ref d,out size);
                if(status!=0 || size>65536) throw new IOException("TDH size "+name+": "+status);
                byte[] b=new byte[size]; status=TdhGetProperty(r,0,IntPtr.Zero,1,ref d,size,b);
                if(status!=0) throw new IOException("TDH property "+name+": "+status);
                return b;
            } finally { Marshal.FreeHGlobal(n); }
        }
        void OnEvent(IntPtr pointer) {
            try {
                Record r=(Record)Marshal.PtrToStructure(pointer,typeof(Record));
                if(r.Provider!=new Guid("2cb15d1d-5fc1-11d2-abe1-00a0c911f518")) return;
                // 10 is a new load; 3 is startup rundown (existing images), tagged separately.
                if(r.Opcode!=10 && r.Opcode!=3) return;
                byte[] addr=GetProperty(pointer,"ImageBase");
                if(addr.Length!=4 && addr.Length!=8) throw new IOException("Unexpected ETW ImageBase width: "+addr.Length);
                ulong imageBase=addr.Length==8 ? BitConverter.ToUInt64(addr,0) : BitConverter.ToUInt32(addr,0);
                // TDH supplies event pointer width independently of process/host ISA.
                if(!Native.IsKernelImageAddress(imageBase,maximumUserAddress)) return;
                string path=Encoding.Unicode.GetString(GetProperty(pointer,"FileName")).TrimEnd('\0');
                uint pid=BitConverter.ToUInt32(GetProperty(pointer,"ProcessId"),0);
                Notice n=new Notice {Kind="Load",EventId=Guid.NewGuid().ToString("N").Substring(0,16),
                    RawPath=path,ProcessId=pid,Opcode=r.Opcode,ObservedUtc=DateTime.UtcNow,
                    EventUtc=DateTime.FromFileTimeUtc(r.Timestamp)};
                if(!incoming.TryAdd(n)) Interlocked.Increment(ref Dropped);
            } catch(Exception e) { Interlocked.Increment(ref DecodeErrors); FatalError="ETW decode failed: "+e.Message; }
        }
        void Decide() {
            try {
                foreach(Notice n in incoming.GetConsumingEnumerable()) {
                    try {
                        n.Path=Native.Normalize(n.RawPath);
                        // Unknown paths need no hash before alert. Known paths must be rehashed:
                        // never trust a cached hash after a replacement at the same path.
                        bool knownPath=false;
                        foreach(string k in approved) if(k.StartsWith(n.Path+"|",StringComparison.OrdinalIgnoreCase)) { knownPath=true; break; }
                        if(knownPath) {
                            n.SHA256=Native.Hash(n.Path);
                            n.Approved=approved.Contains(n.Path+"|"+n.SHA256);
                            n.Reason=n.Approved ? "ApprovedPathAndHash" : "HashMismatch";
                        } else n.Reason="UnapprovedPath";
                    } catch(Exception e) { n.Approved=false; n.Reason="Unverifiable"; n.Detail=e.Message; }
                    if(!n.Approved && !dns.TryAdd(n)) Interlocked.Increment(ref Dropped);
                    // Full inventory enrichment happens on the PowerShell thread, AFTER queuing DNS.
                    Publish(n);
                }
            } catch(Exception e) { FatalError="Decision worker failed: "+e.Message; }
        }
        void Send() {
            try {
                foreach(Notice n in dns.GetConsumingEnumerable()) {
                    string driver=Path.GetFileName(String.IsNullOrEmpty(n.Path)?n.RawPath:n.Path);
                    foreach(string q in Native.Queries(endpoint,driver,n.EventId,token)) {
                        DateTime dispatched=DateTime.UtcNow;
                        // Dispatch record is available even if the resolver later times out.
                        Publish(new Notice {Kind="DnsDispatch",EventId=n.EventId,Query=q,
                            DispatchUtc=dispatched,ObservedUtc=DateTime.UtcNow});
                        int status=Native.SendQuery(q);
                        Publish(new Notice {Kind="DnsResult",EventId=n.EventId,Query=q,
                            DispatchUtc=dispatched,ObservedUtc=DateTime.UtcNow,Detail="DnsQuery status="+status+
                            "; not proof of Canarytoken delivery"});
                    }
                }
            } catch(Exception e) { FatalError="DNS worker failed: "+e.Message; }
        }
        public Notice Read() { Notice n; return output.TryTake(out n)?n:null; }
        public int Backlog { get { return incoming.Count+dns.Count+output.Count; } }
        public void Start() {
            try {
                props=Marshal.AllocHGlobal(4096); Marshal.Copy(new byte[4096],0,props,4096);
                Properties p=new Properties {Size=4096,Guid=new Guid("09b7b622-d45b-46f7-aa8f-49f9f4126fd8"),
                    ClientContext=1,WnodeFlags=0x20000,BufferSize=64,MinimumBuffers=32,MaximumBuffers=128,
                    LogFileMode=0x02000000|0x100,FlushTimer=1,EnableFlags=4,LoggerNameOffset=120};
                Marshal.StructureToPtr(p,props,false);
                uint status=StartTrace(out session,SessionName,props);
                if(status!=0) { session=0; throw new IOException("StartTrace status="+status+
                    ". If 183, another monitor or orphaned session exists; see README."); }
                callback=OnEvent; logger=Marshal.StringToHGlobalUni(SessionName);
                LogFile log=new LogFile {LoggerName=logger,ProcessTraceMode=0x100|0x10000000,
                    Callback=Marshal.GetFunctionPointerForDelegate(callback)};
                trace=OpenTrace(ref log);
                if(trace==UInt64.MaxValue) throw new IOException("OpenTrace error="+Marshal.GetLastWin32Error());
                consumer=new Thread(delegate() {
                    uint result=ProcessTrace(new ulong[]{trace},1,IntPtr.Zero,IntPtr.Zero);
                    if(!stopping) FatalError="ProcessTrace unexpectedly ended, status="+result;
                });
                worker=new Thread(Decide); sender=new Thread(Send);
                consumer.IsBackground=worker.IsBackground=sender.IsBackground=true;
                sender.Start(); worker.Start(); consumer.Start();
            } catch { Dispose(); throw; }
        }
        public string Health() {
            uint s=ControlTrace(session,SessionName,props,0);
            if(s!=0) throw new IOException("ETW health query failed: "+s);
            Properties p=(Properties)Marshal.PtrToStructure(props,typeof(Properties));
            if(p.EventsLost>0 || p.RealTimeBuffersLost>0 || Dropped>0 || DecodeErrors>0)
                throw new IOException("Coverage loss: EventsLost="+p.EventsLost+", BuffersLost="+
                    p.RealTimeBuffersLost+", QueueDropped="+Dropped+", DecodeErrors="+DecodeErrors);
            if(FatalError!=null) throw new IOException(FatalError);
            return "EventsLost=0; BuffersLost=0; QueueDropped=0; DecodeErrors=0; Backlog="+Backlog;
        }
        public void Dispose() {
            if(stopping) return; stopping=true;
            if(session!=0 && props!=IntPtr.Zero) ControlTrace(session,SessionName,props,1);
            if(trace!=UInt64.MaxValue) CloseTrace(trace);
            bool joined=consumer==null || !consumer.IsAlive || consumer.Join(5000);
            incoming.CompleteAdding(); if(worker!=null && worker.IsAlive) worker.Join(5000);
            dns.CompleteAdding(); if(sender!=null && sender.IsAlive) sender.Join(5000);
            // Keep callback/native name alive if a native consumer did not return in time.
            if(joined) {
                if(logger!=IntPtr.Zero) Marshal.FreeHGlobal(logger);
                if(props!=IntPtr.Zero) Marshal.FreeHGlobal(props);
                logger=props=IntPtr.Zero;
            }
            GC.KeepAlive(callback);
        }
    }
}
'@
}
$architectureReport = [DriverCanary.Native]::PlatformInfo()
[DriverCanary.Monitor]::ValidateInterop() | Out-Null
Write-Verbose $architectureReport

function Write-JsonFile($Object, [string]$Path) {
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $tmp = Join-Path $parent ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($tmp, ($Object | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp } }
}
function Get-DriverMetadata([string]$RawPath) {
    $r = [ordered]@{ RawPath=$RawPath; Path=$null; Name=$null; SHA256=$null; Length=$null;
        LastWriteTimeUtc=$null; SignatureStatus='NotChecked'; SignatureType=$null;
        SignatureMessage=$null; SignerSubject=$null; SignerIssuer=$null; SignerThumbprint=$null;
        SignerNotAfterUtc=$null; TimestampSignerSubject=$null; FileVersion=$null;
        ProductName=$null; CompanyName=$null; Error=$null; Approved=$false }
    try {
        $r.Path = [DriverCanary.Native]::Normalize($RawPath)
        $r.Name = [IO.Path]::GetFileName($r.Path)
        $f = Get-Item -LiteralPath $r.Path
        $r.Length=$f.Length; $r.LastWriteTimeUtc=$f.LastWriteTimeUtc.ToString('o')
        $r.SHA256=[DriverCanary.Native]::Hash($r.Path)
        $r.FileVersion=$f.VersionInfo.FileVersion; $r.ProductName=$f.VersionInfo.ProductName
        $r.CompanyName=$f.VersionInfo.CompanyName
        $s=Get-AuthenticodeSignature -LiteralPath $r.Path
        $r.SignatureStatus=[string]$s.Status; $r.SignatureType=[string]$s.SignatureType
        $r.SignatureMessage=$s.StatusMessage
        if ($s.SignerCertificate) {
            $r.SignerSubject=$s.SignerCertificate.Subject; $r.SignerIssuer=$s.SignerCertificate.Issuer
            $r.SignerThumbprint=$s.SignerCertificate.Thumbprint
            $r.SignerNotAfterUtc=$s.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
        }
        if ($s.TimeStamperCertificate) { $r.TimestampSignerSubject=$s.TimeStamperCertificate.Subject }
    } catch { $r.Error=$_.Exception.Message }
    [pscustomobject]$r
}
function Write-Log($Object) {
    # Daily JSONL; retention/forwarding belongs to the endpoint operator.
    $path=Join-Path $DataDirectory ('events-{0}.jsonl' -f [DateTime]::UtcNow.ToString('yyyyMMdd'))
    [IO.File]::AppendAllText($path, (($Object | ConvertTo-Json -Depth 10 -Compress)+[Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
}

switch ($Mode) {
    'SelfTest' {
        Write-Output $architectureReport
        Write-Output ([DriverCanary.Monitor]::ValidateInterop())
        $maxUser=[DriverCanary.Native]::MaximumUserAddress()
        if([DriverCanary.Native]::IsKernelImageAddress($maxUser,$maxUser) -or
            [DriverCanary.Native]::IsKernelImageAddress(0,$maxUser) -or
            -not [DriverCanary.Native]::IsKernelImageAddress([UInt64]::MaxValue,$maxUser)) {
            throw 'Kernel image address boundary test failed'
        }
        Write-Output ('MaximumUserAddress=0x{0:X16}; address boundary checks passed' -f $maxUser)
        $vectors=@{ ''=''; 'f'='MY'; 'fo'='MZXQ'; 'foo'='MZXW6'; 'foob'='MZXW6YQ';
            'fooba'='MZXW6YTB'; 'foobar'='MZXW6YTBOI' }
        foreach($v in $vectors.GetEnumerator()) {
            if ([DriverCanary.Native]::Base32([Text.Encoding]::UTF8.GetBytes($v.Key)) -cne $v.Value) {
                throw "Base32 failed for $($v.Key)"
            }
        }
        foreach($name in @('PROCMON99.SYS', ('long-'*100)+'driver.sys', 'unicode-'+[char]0x96EA+'.sys')) {
            $queries=[DriverCanary.Native]::Queries('LAB-PC',$name,'0123456789abcdef','sample.canarytokens.com')
            foreach($q in $queries) {
                if($q.Length -gt 253) { throw 'FQDN too long' }
                foreach($label in $q.Split('.')) { if($label.Length -gt 63) { throw 'Label too long' } }
            }
        }
        Write-Output 'PASS: RFC 4648 Base32 vectors, DNS label and total length, long/Unicode payload generation. No DNS sent.'
    }
    'Inventory' {
        if (Test-Path -LiteralPath $InventoryPath) { throw 'Inventory exists. Use a new -InventoryPath to preserve your review.' }
        $services=@(Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,PathName,State,Started,StartMode,ServiceType)
        $loaded=@([DriverCanary.Native]::LoadedDriverPaths())
        $pnp=@(Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName,DeviceID,DriverName,DriverVersion,
            DriverDate,InfName,IsSigned,Signer,Manufacturer,DriverProviderName)
        $paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($s in $services) { if($s.PathName) { [void]$paths.Add($s.PathName) } }
        foreach($p in $loaded) { [void]$paths.Add($p) }
        $scanErrors=@()
        $roots=@("$env:SystemRoot\System32\drivers", "$env:SystemRoot\System32\DriverStore\FileRepository") + $ScanRoot
        foreach($root in $roots) {
            Get-ChildItem -LiteralPath $root -Filter '*.sys' -File -Recurse -ErrorAction SilentlyContinue -ErrorVariable +scanErrors |
                ForEach-Object { [void]$paths.Add($_.FullName) }
        }
        $files=@(foreach($p in $paths) { Get-DriverMetadata $p })
        $files=@($files | Sort-Object Path,RawPath -Unique)
        $inventory=[ordered]@{ SchemaVersion=1; Endpoint=$env:COMPUTERNAME; Platform=$architectureReport; CreatedUtc=[DateTime]::UtcNow.ToString('o');
            ScanRoots=$roots; ScanErrors=@($scanErrors | ForEach-Object { $_.ToString() });
            Services=$services; LoadedDriverPaths=$loaded; PnpDriverPackages=$pnp; Drivers=$files }
        Write-JsonFile $inventory $InventoryPath
        $files | Export-Csv -LiteralPath ([IO.Path]::ChangeExtension($InventoryPath,'.csv')) -NoTypeInformation -Encoding UTF8
        Write-Output "Inventory: $InventoryPath ($($files.Count) rows; $($scanErrors.Count) scan errors). No drivers approved."
    }
    'Approve' {
        if(Test-Path -LiteralPath $BaselinePath) { throw 'Baseline exists. Write a new -BaselinePath, review and replace during maintenance.' }
        $inv=Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
        if($inv.SchemaVersion -ne 1) { throw 'Unsupported inventory schema' }
        $approved=@(foreach($r in $inv.Drivers) {
            if($r.Approved -is [bool] -and $r.Approved) {
                if($r.SHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or -not $r.Path) { throw "Invalid approval: $($r.RawPath)" }
                $path=[DriverCanary.Native]::Normalize($r.Path)
                if([DriverCanary.Native]::Hash($path) -ne $r.SHA256) { throw "File changed since review: $path" }
                [pscustomobject]@{Path=$path;SHA256=$r.SHA256.ToUpperInvariant()}
            }
        })
        if($approved.Count -eq 0) { throw 'No rows have Boolean Approved=true. Review inventory.json first.' }
        Write-JsonFile ([ordered]@{SchemaVersion=1;CreatedUtc=[DateTime]::UtcNow.ToString('o');
            SourceEndpoint=$inv.Endpoint;Drivers=$approved}) $BaselinePath
        Write-Output "Approved $($approved.Count) path/hash pairs: $BaselinePath"
    }
    'TestDns' {
        $id=[Guid]::NewGuid().ToString('N').Substring(0,16)
        foreach($q in [DriverCanary.Native]::Queries($env:COMPUTERNAME,$TestDriverName,$id,$Token)) {
            $time=[DateTime]::UtcNow.ToString('o')
            $status=[DriverCanary.Native]::SendQuery($q)
            Write-Log @{Kind='ManualDnsTest';EventId=$id;DispatchUtc=$time;Query=$q;DnsStatus=$status}
            Write-Output "DNS attempted: $q (status=$status). Verify receipt in Canarytokens; DNS status alone is not delivery confirmation."
        }
    }
    'Monitor' {
        $Token=[DriverCanary.Native]::CheckToken($Token)
        $base=Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
        if($base.SchemaVersion -ne 1) { throw 'Unsupported baseline schema' }
        $keys=@(foreach($r in $base.Drivers) {
            if(-not $r.Path -or $r.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Malformed baseline entry' }
            ([DriverCanary.Native]::Normalize($r.Path))+'|'+$r.SHA256.ToUpperInvariant()
        })
        if($keys.Count -eq 0) { throw 'Empty allowlist; refusing a likely misconfiguration' }
        $monitor=[DriverCanary.Monitor]::new([string[]]$keys,$Token,$env:COMPUTERNAME)
        try {
            $monitor.Start()
            Write-Log @{Kind='MonitorStarted';Utc=[DateTime]::UtcNow.ToString('o');Endpoint=$env:COMPUTERNAME;
                Platform=$architectureReport;MaximumUserAddress=('0x{0:X16}' -f [DriverCanary.Native]::MaximumUserAddress());
                BaselinePath=$BaselinePath;BaselineSHA256=[DriverCanary.Native]::Hash($BaselinePath)}
            Write-Host 'ETW active. Awaiting kernel image loads; startup rundown is reported separately. Ctrl+C stops.'
            $healthAt=[DateTime]::UtcNow
            while($true) {
                if($monitor.FatalError) { throw $monitor.FatalError }
                if([DateTime]::UtcNow -ge $healthAt) {
                    $health=$monitor.Health()
                    Write-Log @{Kind='Health';Utc=[DateTime]::UtcNow.ToString('o');Detail=$health}
                    $healthAt=[DateTime]::UtcNow.AddSeconds(10)
                }
                $n=$monitor.Read()
                if($null -eq $n) { Start-Sleep -Milliseconds 50; continue }
                Write-Log $n
                if($n.Kind -eq 'Load') {
                    $origin=if($n.Opcode -eq 10){'NewLoad'}else{'ExistingAtTraceStart'}
                    if(-not $n.Approved) { Write-Warning "$origin $($n.RawPath): $($n.Reason) [$($n.EventId)]" }
                    # This enrichment cannot hold up the independent C# decision/DNS workers.
                    $meta=Get-DriverMetadata $n.RawPath
                    Write-Log @{Kind='Enrichment';EventId=$n.EventId;Origin=$origin;
                        CollectedUtc=[DateTime]::UtcNow.ToString('o');Metadata=$meta}
                }
            }
        } catch {
            Write-Log @{Kind='MonitorFailed';Utc=[DateTime]::UtcNow.ToString('o');Error=$_.Exception.Message}
            throw
        } finally {
            $monitor.Dispose()
            while($null -ne ($last=$monitor.Read())) { Write-Log $last }
            Write-Log @{Kind='MonitorStopped';Utc=[DateTime]::UtcNow.ToString('o')}
        }
    }
}
