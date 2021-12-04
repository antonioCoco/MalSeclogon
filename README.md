# MalSeclogon
A little tool to play with the Seclogon service.

Full technical details at --> 

## Usage
```
        MalSeclogon v0.1
        @splinter_code

Mandatory args:
-p Pid of the process to spoof the PPID through seclogon service

Other args:
-d Dump lsass method
        1 = Dump lsass by using leaked handles
        2 = Dump lsass by using leaked handles and cloned lsass process
-o Output path of the dump (default C:\lsass.dmp)
-c Commandline of the spoofed process, default: cmd.exe (not compatible with -d)

Examples:
- Run a process with a spoofed PPID:
        Malseclogon.exe -p [PPID] -c cmd.exe
- Dump lsass by using leaked handles:
        Malseclogon.exe -p [lsassPid] -d 1
- Dump lsass by using leaked handles and cloned lsass process:
        Malseclogon.exe -p [lsassPid] -d 2

```
