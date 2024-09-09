# sys-stalker

Detect and analyze malware using eBPF.

## Prerequisites

```
$ sudo dnf install -y bcc bcc-tools bcc-devel python3-bcc bpftrace reptyr
```

## Workflow

Check if the binary is dynamically linked:

```
$ ldd snitch
	linux-vdso.so.1 (0x00007f0c16da8000)
	libc.so.6 => /lib64/libc.so.6 (0x00007f0c16b9a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f0c16daa000)
```

Check dynamic symbols:

```
$ objdump --dynamic-syms snitch

snitch:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*	0000000000000000 (GLIBC_2.34) __libc_start_main
0000000000000000      DF *UND*	0000000000000000 (GLIBC_2.2.5) puts
0000000000000000      DF *UND*	0000000000000000 (GLIBC_2.2.5) getpid
0000000000000000      DF *UND*	0000000000000000 (GLIBC_2.2.5) strlen
0000000000000000      DF *UND*	0000000000000000 (GLIBC_2.2.5) send
...
```

We can attach `uprobe`s to these functions, see https://github.com/gemesa/sys-stalker/blob/main/lab/snitch/trace_snitch.py#L73.

Now this would be way too easy. Target binaries are often obfuscated (using `dlopen`, calling syscalls directly, etc.). In such cases my preferred method is to use `strace` to get a quick high-level overview. The downside to `strace` is that the binary can detect if it is being traced.

eBPF tracing can not be detected though so we can use a simple oneliner like this:

```
$ sudo bpftrace -e 'tracepoint:syscalls:sys_enter_* /pid == 58715/ { printf("syscall: %s\n", probe); }'
Attaching 357 probes...
syscall: tracepoint:syscalls:sys_enter_newfstatat
syscall: tracepoint:syscalls:sys_enter_access
syscall: tracepoint:syscalls:sys_enter_close
syscall: tracepoint:syscalls:sys_enter_rt_sigprocmask
syscall: tracepoint:syscalls:sys_enter_rt_sigprocmask
syscall: tracepoint:syscalls:sys_enter_execve
...
```

Once we see the list of the syscalls we can attach targeted probes to those we are interested in, see https://github.com/gemesa/sys-stalker/blob/main/lab/execve/trace_execve.py#L60.
