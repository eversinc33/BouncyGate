# HellsGate Trampoline

This is a modified version of @zimawhit3's implementation of HellsGate in Nim, with additionally making sure that all syscalls go through NTDLL, by replacing the syscall instructions with a JMP to a syscall instruction in NTDLL.

The syscalls are then used to patch AMSI as a PoC.

## Credits

props to  for their paper on this technique.
If you would like to learn more about how HellsGate works, you can find smelly__vx's (@RtlMateusz) and am0nsec's (@am0nsec) paper at the [Vx-Underground Github](https://github.com/vxunderground/VXUG-Papers/tree/main/Hells%20Gate).
