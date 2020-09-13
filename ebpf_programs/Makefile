

CFLAGS = -D__KERNEL__ -D__ASM_SYSREG_H \
	-Wunused \
	-Wall \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-fno-stack-protector \
	-Wno-pointer-sign \

CLANG ?= clang
LLC ?= llc
EXTRA_CFLAGS ?= -O2 -S -emit-llvm

# if you want to compile against custom kernel headers instead of /usr/include
# include LINUX_INCLUDE on the clang command below. Else, it will just pick up
# from /usr/include 

# Change here to point to actual headers location if needed (other than default)
UNAME=$(shell uname -r)
#LINUX_HEADERS ?= /lib/modules/$(UNAME)

LINUX_HEADERS ?= /root/hdrs
LINUX_INCLUDE ?= -I $(LINUX_HEADERS)/arch/x86/include \
	-I $(LINUX_HEADERS)/arch/x86/include/generated/uapi \
	-I $(LINUX_HEADERS)/arch/x86/include/generated \
	-I $(LINUX_HEADERS)/include \
	-I $(LINUX_HEADERS)/arch/x86/include/uapi \
	-I $(LINUX_HEADERS)/include/uapi \
	-I $(LINUX_HEADERS)/include/generated/uapi \


#LINUX_INCLUDE ?= -I $(LINUX_HEADERS)/build/arch/x86/include \
	-I $(LINUX_HEADERS)/build/arch/x86/include/generated/uapi \
	-I $(LINUX_HEADERS)/build/arch/x86/include/generated \
	-I $(LINUX_HEADERS)/build/include \
	-I $(LINUX_HEADERS)/build/arch/x86/include/uapi \
	-I $(LINUX_HEADERS)/build/include/uapi \
	-include $(LINUX_HEADERS)/build/include/linux/kconfig.h \
	-I $(LINUX_HEADERS)/build/include/generated/uapi 

ELFS = elfs
SRC = src

SRCS = tls.c
OBJS = $(SRCS:%.c=$(ELFS)/%.o)

all: $(OBJS)

$(ELFS)/%.o: $(SRC)/%.c
	$(CLANG) $(CFLAGS) $(EXTRA_CFLAGS) -c $< \
	-I./include $(LINUX_INCLUDE) -o -| $(LLC) -march=bpf -filetype=obj -o $@

.PHONY: clean
clean:
	rm -f elfs/*.o


# proxy config

tc-q:
	tc qdisc add dev eth0 clsact

attach-tc:
	tc filter add dev eth0 ingress bpf da obj elfs/proxy.o sec ingress
	tc filter add dev eth0 egress bpf da obj elfs/proxy.o sec egress

remove-tc:
	tc filter del dev eth0 ingress
	tc filter del dev eth0 egress

show-tc:
	tc filter show dev eth0 ingress
	tc filter show dev eth0 egress

log:
	cat /sys/kernel/debug/tracing/trace_pipe

show:
	ip link show dev lo

off:
	ip link set dev lo xdpgeneric off
