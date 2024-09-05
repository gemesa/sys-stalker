from __future__ import print_function
from bcc import BPF
import sys

if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} PID")
    exit()
pid = sys.argv[1]

bpf_text = """
#include <uapi/linux/ptrace.h>

int trace_send(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    char data[256] = {};
    u64 length = PT_REGS_PARM3(ctx);
    if (length > 256)
        length = 256;

    if (PT_REGS_PARM2(ctx))
        bpf_probe_read_user(&data, length, (void *)PT_REGS_PARM2(ctx));

    bpf_trace_printk("send data: %s\\n", data);
    bpf_trace_printk("send length: %llu\\n", length);
    
    return 0;
}

int trace_getaddrinfo(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    char nodename[256] = {};
    if (PT_REGS_PARM1(ctx))
        bpf_probe_read_user(&nodename, sizeof(nodename), (void *)PT_REGS_PARM1(ctx));

    char port[7] = {};
    if (PT_REGS_PARM2(ctx))
        bpf_probe_read_user(&port, sizeof(port), (void *)PT_REGS_PARM2(ctx));

    bpf_trace_printk("getaddrinfo nodename: %s\\n", nodename);
    bpf_trace_printk("getaddrinfo port: %s\\n", port);

    return 0;
}

int trace_uname(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != PID)
        return 0;

    bpf_trace_printk("uname called\\n");
    return 0;
}

int trace_getpid(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != PID)
        return 0;

    bpf_trace_printk("getpid called\\n");
    return 0;
}
"""
bpf_text = bpf_text.replace('PID', pid)
b = BPF(text=bpf_text)

try:
    b.attach_uprobe(name="c", sym="getpid", fn_name="trace_getpid")
    print("Attached to getpid")
except Exception as e:
    print(f"Failed to attach to getpid: {e}")

try:
    b.attach_uprobe(name="c", sym="uname", fn_name="trace_uname")
    print("Attached to uname")
except Exception as e:
    print(f"Failed to attach to uname: {e}")

try:
    b.attach_uprobe(name="c", sym="send", fn_name="trace_send")
    print("Attached to send")
except Exception as e:
    print(f"Failed to attach to send: {e}")

try:
    b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo")
    print("Attached to getaddrinfo")
except Exception as e:
    print(f"Failed to attach to getaddrinfo: {e}")

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "EVENT"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    task = task.decode('utf-8', 'replace')
    msg = msg.decode('utf-8', 'replace')
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
