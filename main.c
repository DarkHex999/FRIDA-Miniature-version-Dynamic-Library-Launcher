#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/sched/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mini-Frida Developer");
MODULE_DESCRIPTION("Miniature Dynamic Library Launcher");
MODULE_VERSION("1.0");

#define DEVICE_NAME "mini_frida"
#define CLASS_NAME "mini_frida_class"

#define IOC_MAGIC 'k'
struct inject_args {
    pid_t pid;
    char library_path[256];
    unsigned long dlopen_addr;
};
#define IOCTL_INJECT_LIB _IOW(IOC_MAGIC, 1, struct inject_args)

static int major_number;
static struct class* mini_frida_class = NULL;
static struct device* mini_frida_device = NULL;

#ifdef KALLSYMS_ADDR
typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = (kallsyms_lookup_name_t)KALLSYMS_ADDR;
#endif

// وظيفة لحجز ذاكرة وكتابة المسار وتعديل السجلات
static int perform_injection(struct inject_args* args) {
    struct task_struct* task;
    struct mm_struct* mm;
    unsigned long allocated_addr = 0;
    struct pt_regs* regs;

    rcu_read_lock();
    task = find_task_by_vpid(args->pid);
    if (!task) {
        rcu_read_unlock();
        pr_err("mini_frida: Target process %d not found\n", args->pid);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        pr_err("mini_frida: Failed to get mm for task %d\n", args->pid);
        put_task_struct(task);
        return -EINVAL;
    }

    // الانتقال مؤقتاً إلى مساحة الذاكرة الخاصة بالعملية المستهدفة
    use_mm(mm);

    // حجز مساحة ذاكرة قابلة للقراءة والكتابة والتنفيذ (RWX)
    down_write(&mm->mmap_sem);
    allocated_addr = vm_mmap(NULL, 0, PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE, 0);
    up_write(&mm->mmap_sem);

    if (IS_ERR_VALUE(allocated_addr)) {
        pr_err("mini_frida: Failed to allocate memory in target process\n");
        unuse_mm(mm);
        mmput(mm);
        put_task_struct(task);
        return -ENOMEM;
    }

    // نسخ مسار المكتبة (.so) إلى منطقة الذاكرة المحجوزة في العملية المستهدفة
    if (copy_to_user((void __user*)allocated_addr, args->library_path, strlen(args->library_path) + 1)) {
        pr_err("mini_frida: Failed to write library path to target memory\n");
        unuse_mm(mm);
        mmput(mm);
        put_task_struct(task);
        return -EFAULT;
    }

    // جلب سجلات المعالج الخاصة بالعملية (بنية ARM64)
    regs = task_pt_regs(task);
    if (regs) {
        // السجل X0 يحمل المعامل الأول لـ dlopen (مسار المكتبة)
        regs->regs[0] = allocated_addr;
        // السجل X1 يحمل المعامل الثاني لـ dlopen (أعلام التحميل مثل RTLD_NOW)
        regs->regs[1] = 2;

        // توجيه مؤشر البرنامج PC إلى دالة dlopen المستهدفة
        regs->pc = args->dlopen_addr;

        pr_info("mini_frida: Target registers modified. PC: 0x%lx, X0: 0x%lx\n",
            args->dlopen_addr, allocated_addr);
    }
    else {
        pr_err("mini_frida: Failed to retrieve process registers\n");
    }

    // إعادة السياق إلى ما كان عليه
    unuse_mm(mm);
    mmput(mm);
    put_task_struct(task);
    return 0;
}

static long device_ioctl(struct file* file, unsigned int cmd, unsigned long arg) {
    struct inject_args kargs;

    if (cmd == IOCTL_INJECT_LIB) {
        if (copy_from_user(&kargs, (void __user*)arg, sizeof(kargs))) {
            return -EFAULT;
        }
        return perform_injection(&kargs);
    }
    return -EINVAL;
}

static struct file_operations fops = {
    .unlocked_ioctl = device_ioctl,
    .owner = THIS_MODULE,
};

static int __init mini_frida_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("mini_frida: Failed to register device\n");
        return major_number;
    }

    mini_frida_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(mini_frida_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mini_frida_class);
    }

    mini_frida_device = device_create(mini_frida_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mini_frida_device)) {
        class_destroy(mini_frida_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mini_frida_device);
    }

    pr_info("mini_frida: Loaded. Kallsyms Base Configured: %s\n",
#ifdef KALLSYMS_ADDR
        "YES"
#else
        "NO"
#endif
    );
    return 0;
}

static void __exit mini_frida_exit(void) {
    device_destroy(mini_frida_class, MKDEV(major_number, 0));
    class_unregister(mini_frida_class);
    class_destroy(mini_frida_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    pr_info("mini_frida: Unloaded\n");
}

module_init(mini_frida_init);
module_exit(mini_frida_exit);