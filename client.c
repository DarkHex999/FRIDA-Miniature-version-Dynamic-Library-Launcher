#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define IOC_MAGIC 'k'
struct inject_args {
    pid_t pid;
    char library_path[256];
    unsigned long dlopen_addr;
};
#define IOCTL_INJECT_LIB _IOW(IOC_MAGIC, 1, struct inject_args)

// دالة للبحث عن عنوان بداية مكتبة الربط الديناميكي داخل خرائط الذاكرة
unsigned long find_linker_base(pid_t pid, const char* lib_name) {
    char maps_path[64];
    FILE* fp;
    char line[512];
    unsigned long start_addr = 0;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (!fp) {
        perror("[-] Failed to open process maps");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-", &start_addr) == 1) {
                break;
            }
        }
    }

    fclose(fp);
    return start_addr;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <PID> <path_to_so_file>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char* so_path = argv[2];

    // تحديد قاعدة العنوان للـ linker64 في نظام أندرويد
    unsigned long base_addr = find_linker_base(pid, "/system/bin/linker64");
    if (!base_addr) {
        base_addr = find_linker_base(pid, "/system/bin/linker");
    }

    if (!base_addr) {
        fprintf(stderr, "[-] Error: Could not resolve linker base address in process %d\n", pid);
        return 1;
    }

    // إزاحة افتراضية لدالة dlopen داخل linker64 (يمكن تعديلها وفقاً للإصدار المستهدف بدقة)
    unsigned long dlopen_offset = 0x13cc0;
    unsigned long dlopen_addr = base_addr + dlopen_offset;

    printf("[+] Found Linker Base Address: 0x%lx\n", base_addr);
    printf("[+] Calculated dlopen Address: 0x%lx (Offset: 0x%lx)\n", dlopen_addr, dlopen_offset);

    int fd = open("/dev/mini_frida", O_RDWR);
    if (fd < 0) {
        perror("[-] Error opening /dev/mini_frida. Did you run insmod?");
        return 1;
    }

    struct inject_args args;
    args.pid = pid;
    strncpy(args.library_path, so_path, sizeof(args.library_path) - 1);
    args.library_path[sizeof(args.library_path) - 1] = '\0';
    args.dlopen_addr = dlopen_addr;

    printf("[+] Dispatching injection request for PID %d...\n", pid);
    if (ioctl(fd, IOCTL_INJECT_LIB, &args) < 0) {
        perror("[-] IOCTL Request Failed");
        close(fd);
        return 1;
    }

    printf("[+] Injection request handled successfully. Check dmesg for kernel-side logs.\n");
    close(fd);
    return 0;
}