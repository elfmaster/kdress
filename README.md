# kdress
Transform vmlinuz into a fully debuggable vmlinux that can be used with /proc/kcore

# Use cases
This tools makes it possible to use /proc/kcore for debugging or forensics analysis
without having to recompile your kernel with symbols, or download a special debug
kernel image. This software is actually from a much larger project called 'Kernel Voodoo'
which is still private. Kernel Voodoo uses 'kdress' to create a vmlinux that can be
used as a way to easily navigate kernel memory by symbol and also have a valid signature to
compare code against from /proc/kcore.

# Example
ryan@elfmaster:~/kdress$ sudo ./kdress vmlinuz-`uname -r` vmlinux /boot/System.map-`uname -r`

[+] vmlinux has been successfully extracted
[+] vmlinux has been successfully instrumented with a complete ELF symbol table.

ryan@elfmaster:~/kdress$ sudo readelf -s vmlinux | grep sys_call_table
 33268: ffffffff81801400  4368 OBJECT  GLOBAL DEFAULT    4 sys_call_table
 33421: ffffffff81809ca0  2928 OBJECT  GLOBAL DEFAULT    4 ia32_sys_call_table

