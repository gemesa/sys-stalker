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

eBPF tracing can not be detected though. First execute the target and stop it immediately (we do this to obtain its PID):

```
$ ./snitch & pid=$!; kill -STOP $pid
[1] 50389
                                                                                                                      
[1]  + suspended (signal)  ./snitch
```

Then start tracing:

```
$ sudo bpftrace -e 'tracepoint:syscalls:sys_enter_* /pid == 50389/ { printf("syscall: %s\n", probe); }'
Attaching 357 probes...
```
Resume the process:

```
$ kill -CONT 50389 && reptyr 50389
PID: 50389
...
```
Observe the syscalls in real-time:

```
$ sudo bpftrace -e 'tracepoint:syscalls:sys_enter_* /pid == 50389/ { printf("syscall: %s\n", probe); }'
Attaching 357 probes...
syscall: tracepoint:syscalls:sys_enter_newfstatat
syscall: tracepoint:syscalls:sys_enter_access
syscall: tracepoint:syscalls:sys_enter_close
syscall: tracepoint:syscalls:sys_enter_rt_sigprocmask
syscall: tracepoint:syscalls:sys_enter_rt_sigprocmask
syscall: tracepoint:syscalls:sys_enter_execve
...
```

Once we see the list of the syscalls we can attach targeted probes to those we are interested in, see https://github.com/gemesa/sys-stalker/blob/main/lab/kprobe-sendto/kprobe-sendto/src/main.rs#L43 or https://github.com/gemesa/sys-stalker/blob/main/lab/execve/trace_execve.py#L60.

The available probes can be listed with:

```
$ sudo bpftrace -l '*<your-symbol>*'
```

For example:

```
$ sudo bpftrace -l '*sendto*'
kfunc:sunrpc:__probestub_rpc_xdr_sendto
kfunc:sunrpc:__probestub_svc_xdr_sendto
kfunc:sunrpc:__traceiter_rpc_xdr_sendto
kfunc:sunrpc:__traceiter_svc_xdr_sendto
kfunc:sunrpc:bc_sendto
kfunc:sunrpc:svc_tcp_sendto
kfunc:sunrpc:svc_udp_sendto
kfunc:vmlinux:__ia32_sys_sendto
kfunc:vmlinux:__sys_sendto
kfunc:vmlinux:__x64_sys_sendto
kprobe:__ia32_sys_sendto
kprobe:__probestub_rpc_xdr_sendto
kprobe:__probestub_svc_xdr_sendto
kprobe:__sys_sendto
kprobe:__traceiter_rpc_xdr_sendto
kprobe:__traceiter_svc_xdr_sendto
kprobe:__x64_sys_sendto
kprobe:bc_sendto
kprobe:svc_tcp_sendto
kprobe:svc_udp_sendto
rawtracepoint:rpc_xdr_sendto
rawtracepoint:svc_xdr_sendto
tracepoint:sunrpc:rpc_xdr_sendto
tracepoint:sunrpc:svc_xdr_sendto
tracepoint:syscalls:sys_enter_sendto
tracepoint:syscalls:sys_exit_sendto
```
