#!/usr/bin/python3
from bcc import BPF
import ctypes

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAXARG 10
#define ARGLEN 45

BPF_PERF_OUTPUT(output);

struct data_t {     
   int pid;
   int uid;
   char command[16];
   char args[MAXARG][ARGLEN];
};

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *argv,
    const char __user *const __user *envp) {

    int i;
    const char *argp;

    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));

    for (i = 0; i < MAXARG; i++) {
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (argp == NULL) {
            break;
        }
        bpf_probe_read_user_str(&data.args[i], sizeof(data.args[i]), argp);
    }

    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("uid", ctypes.c_int),
        ("command", ctypes.c_char * 16),
        ("args", (ctypes.c_char * 45) * 10)
    ]

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="syscall__execve")

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"{event.pid} {event.uid} {event.command.decode()}", end=" ")

    for arg in event.args:
        arg_str = ctypes.string_at(arg).decode('utf-8', 'replace')
        if not arg_str:
            break
        print(arg_str, end=" ")
    print()

b["output"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
