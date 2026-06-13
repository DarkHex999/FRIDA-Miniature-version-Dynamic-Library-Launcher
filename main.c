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
#include <linux/version.h>

// التحقق من توافق ملفات رأس الجدولة وإدارة الذاكرة للإصدارات القديمة
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#else
#include <linux/sched.h>
#include <linux/mmu_context.h>
#endif

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

// -------------------------------------------------------------
// تعريف أنواع ومؤشرات الدوال للحل الديناميكي (Dynamic Resolving)
// -------------------------------------------------------------
#ifdef KALLSYMS_ADDR
typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = (kallsyms_lookup_name_t)KALLSYMS_ADDR;

static inline unsigned long my_kallsyms(const char* name) {
    if (my_kallsyms_lookup_name)
        return my_kallsyms_lookup_name(name);
    return 0;
}
#else
static inline unsigned long my_kallsyms(const char* name) { return 0; }
#endif

// تعريف أنواع الدوال الأصلية (Typedefs)
typedef struct task_struct* (*t_find_task_by_vpid)(pid_t nr);
typedef struct mm_struct* (*t_get_task_mm)(struct task_struct* task);
typedef void (*t_mmput)(struct mm_struct* mm);
typedef void (*t_use_mm)(struct mm_struct* mm);
typedef void (*t_unuse_mm)(struct mm_struct* mm);
typedef void (*t_rcu_func)(void);
typedef void (*t_put_task)(struct task_struct* t);

// الإعلان عن مؤشرات الدوال العالمية
static t_find_task_by_vpid fn_find_task = NULL;
static t_get_task_mm fn_get_task_mm = NULL;
static t_mmput fn_mmput = NULL;
static t_use_mm fn_use_mm = NULL;
static t_unuse_mm fn_unuse_mm = NULL;
static t_rcu_func fn_rcu_read_lock = NULL;
static t_rcu_func fn_rcu_read_unlock = NULL;
static t_put_task fn_put_task_struct = NULL;

// ماكرو المطور لحل الرموز والتحقق من نجاحها
#define RESOLVE_FN(ptr, sym)                                        \
    do {                                                             \
        (ptr) = (__typeof__(ptr)) my_kallsyms(sym);                 \
        if (!(ptr)) {                                               \
            printk(KERN_ERR "mini_frida: [-] FAILED to resolve [%s]\n", sym); \
            return -ENOENT;                                          \
        }                                                            \
    } while (0)

static int resolve_all_symbols(void) {
    RESOLVE_FN(fn_find_task, "find_task_by_vpid");
    RESOLVE_FN(fn_get_task_mm, "get_task_mm");
    RESOLVE_FN(fn_mmput, "mmput");
    RESOLVE_FN(fn_use_mm, "use_mm");
    RESOLVE_FN(fn_unuse_mm, "unuse_mm");

    // حل دوال RCU وإدارة الهيكل اختيارياً لتجنب مشاكل التجميع المباشر
    fn_rcu_read_lock = (t_rcu_func)my_kallsyms("__rcu_read_lock");
    fn_rcu_read_unlock = (t_rcu_func)my_kallsyms("__rcu_read_unlock");
    fn_put_task_struct = (t_put_task)my_kallsyms("__put_task_struct");

    return 0;
}

// وظيفة لحجز ذاكرة وكتابة المسار وتعديل السجلات
static int perform_injection(struct inject_args* args) {
    struct task_struct* task;
    struct mm_struct* mm;
    unsigned long allocated_addr = 0;
    struct pt_regs* regs;

    if (fn_rcu_read_lock) fn_rcu_read_lock();

    // استدعاء دالة البحث ديناميكياً
    task = fn_find_task(args->pid);
    if (!task) {
        if (fn_rcu_read_unlock) fn_rcu_read_unlock();
        pr_err("mini_frida: Target process %d not found\n", args->pid);
        return -ESRCH;
    }

    get_task_struct(task);
    if (fn_rcu_read_unlock) fn_rcu_read_unlock();

    // استدعاء جلب ذاكرة العملية ديناميكياً
    mm = fn_get_task_mm(task);
    if (!mm) {
        pr_err("mini_frida: Failed to get mm for task %d\n", args->pid);
        if (fn_put_task_struct) fn_put_task_struct(task);
        return -EINVAL;
    }

    // الانتقال مؤقتاً إلى مساحة الذاكرة الخاصة بالعملية المستهدفة ديناميكياً
    fn_use_mm(mm);

    // حجز مساحة ذاكرة قابلة للقراءة والكتابة والتنفيذ (RWX)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    down_write(&mm->mmap_lock);
#else
    down_write(&mm->mmap_sem);
#endif

    allocated_addr = vm_mmap(NULL, 0, PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    up_write(&mm->mmap_lock);
#else
    up_write(&mm->mmap_sem);
#endif

    if (IS_ERR_VALUE(allocated_addr)) {
        pr_err("mini_frida: Failed to allocate memory in target process\n");
        fn_unuse_mm(mm);
        fn_mmput(mm);
        if (fn_put_task_struct) fn_put_task_struct(task);
        return -ENOMEM;
    }

    // نسخ مسار المكتبة (.so) إلى منطقة الذاكرة المحجوزة في العملية المستهدفة
    if (copy_to_user((void __user*)allocated_addr, args->library_path, strlen(args->library_path) + 1)) {
        pr_err("mini_frida: Failed to write library path to target memory\n");
        fn_unuse_mm(mm);
        fn_mmput(mm);
        if (fn_put_task_struct) fn_put_task_struct(task);
        return -EFAULT;
    }

    // جلب سجلات المعالج الخاصة بالعملية والتعديل عليها حسب المعمارية المستهدفة
    regs = task_pt_regs(task);
    if (regs) {
#if defined(CONFIG_X86_64)
        // معمارية x86_64 (الحواسيب الشخصية)
        regs->di = allocated_addr;
        regs->si = 2; // RTLD_NOW
        regs->ip = args->dlopen_addr;
        pr_info("mini_frida (x86_64): Target registers modified. IP: 0x%lx, RDI: 0x%lx\n",
            args->dlopen_addr, allocated_addr);
#elif defined(CONFIG_ARM64)
        // معمارية ARM64 (أندرويد)
        regs->regs[0] = allocated_addr;
        regs->regs[1] = 2; // RTLD_NOW
        regs->pc = args->dlopen_addr;
        pr_info("mini_frida (ARM64): Target registers modified. PC: 0x%lx, X0: 0x%lx\n",
            args->dlopen_addr, allocated_addr);
#else
#error "Unsupported architecture for register modification"
#endif
    }
    else {
        pr_err("mini_frida: Failed to retrieve process registers\n");
    }

    // إعادة السياق وتحرير المراجع ديناميكياً
    fn_unuse_mm(mm);
    fn_mmput(mm);
    if (fn_put_task_struct) fn_put_task_struct(task);
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
    // حل الرموز ديناميكياً أولاً، وإذا فشل يتم إلغاء التحميل لمنع انهيار النواة (Kernel Panic)
    if (resolve_all_symbols() != 0) {
        pr_err("mini_frida: Symbol resolution failed. Unloading...\n");
        return -ENOENT;
    }

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

    pr_info("mini_frida: Loaded successfully.\n");
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
