# Makefile - Miniature Frida/Cheat Engine Dynamic Library Launcher

obj-m += main.o

# تحديد مسار بناء كود الكيرنل الافتراضي للينكس
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# تعريف المسار الصحيح لـ NDK داخل نظام لينكس (WSL)
NDK ?= /home/darkhex/android-ndk-r25c
CC_ANDROID := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android29-clang

# التحقق من وجود قيمة لـ KALLSYMS_ADDR وتمريرها كتعريف برميجي (Macro)
ifdef KALLSYMS_ADDR
    EXTRA_CFLAGS += -DKALLSYMS_ADDR=$(KALLSYMS_ADDR)
endif

all: client kernel_module

kernel_module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

client: client.c
	$(CC_ANDROID) -o client client.c -static

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f client
