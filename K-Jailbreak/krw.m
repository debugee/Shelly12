//
//  krw.m
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/17.
//

#include "krw.h"
#include "sock_port/exploit.h"
#include "sock_port/exploit.h"

static task_t tfp0 = MACH_PORT_NULL;
static uint64_t kslide = 0;

void setKSlide(uint64_t addr) {
    kslide = addr;
}

void setTFP0(task_t task) {
    tfp0 = task;
}

task_t getTFP0() {
    if(tfp0 != MACH_PORT_NULL)
        return tfp0;
    
    task_t tfp0 = get_tfp0();
    setTFP0(tfp0);
    return tfp0;
}


static bool isKBase(uint64_t kbase) {
    
    uint64_t data = kread32(kbase);
    
    if(data == MH_MAGIC_64)
        return true;
    
    return false;
}

uint64_t getKBase() {
    io_service_t serviceIOSR = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (!MACH_PORT_VALID(serviceIOSR))
        return 0;
    
    io_connect_t client = MACH_PORT_NULL;
    kern_return_t ret = IOServiceOpen(serviceIOSR, mach_task_self(), 0, &client);
    if (ret != KERN_SUCCESS || !MACH_PORT_VALID(client)) {
        IOServiceClose(serviceIOSR);
        return 0;
    }
    
    uint64_t iosruc_port = find_port(client, task_self_addr());
    uint64_t iosruc_addr = kread64(iosruc_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t iosruc_vtab = kread64(iosruc_addr);
    
    uint64_t get_trap_for_index_addr = kread64(iosruc_vtab + KSTRUCT_OFFSET_GET_TRAP_FOR_INDEX * 0x8);
    if(!get_trap_for_index_addr) {
        IOServiceClose(serviceIOSR);
        return 0;
    }
    
#define KERNEL_HEADER_OFFSET        0x4000
#define KERNEL_SLIDE_STEP           0x10000
    uint64_t kernel_base = (get_trap_for_index_addr & ~(KERNEL_SLIDE_STEP - 1)) + KERNEL_HEADER_OFFSET;
    while (true) {
        if(isKBase(kernel_base))
            break;
        kernel_base -= 0x1000;
    }
    
    IOServiceClose(serviceIOSR);

    setKSlide(kernel_base - KERNEL_IMAGE_BASE);
    return kernel_base;
}


uint64_t getProc(pid_t pid) {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_internal.h#L193
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/queue.h#L470
    
    uint64_t proc = kread64(KERNPROC + kslide);
    
    while (true) {
        if(kread32(proc + PROC_P_PID_OFF) == pid) {
            return proc;
        }
        proc = kread64(proc + PROC_P_LIST_LE_PREV_OFF);
    }
    
    return 0;
}

kern_return_t kread_buf(uint64_t addr, void *buf, size_t sz) {
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_vm_size_t read_sz, out_sz = 0;

    while(sz != 0) {
        read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
            return KERN_FAILURE;
        }
        p += read_sz;
        sz -= read_sz;
        addr += read_sz;
    }
    return KERN_SUCCESS;
}

void *kread_buf_alloc(uint64_t addr, mach_vm_size_t read_sz) {
    void *buf = malloc(read_sz);

    if(buf) {
        if(kread_buf(addr, buf, read_sz) == KERN_SUCCESS) {
            return buf;
        }
        free(buf);
    }
    return NULL;
}

kern_return_t
kwrite_buf(uint64_t addr, const void *buf, mach_msg_type_number_t sz) {
    vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_msg_type_number_t write_sz;

    while(sz != 0) {
        write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        p += write_sz;
        sz -= write_sz;
        addr += write_sz;
    }
    return KERN_SUCCESS;
}

uint32_t kread32(uint64_t where) {
    uint32_t out;
    kread_buf(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kread64(uint64_t where) {
    uint64_t out;
    kread_buf(where, &out, sizeof(uint64_t));
    return out;
}

void kwrite32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite_buf(where, &_what, sizeof(uint32_t));
}

void kwrite64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite_buf(where, &_what, sizeof(uint64_t));
}

unsigned long kstrlen(uint64_t string) {
    if (!string) return 0;
    
    unsigned long len = 0;
    char ch = 0;
    int i = 0;
    while (true) {
        kread_buf(string + i, &ch, 1);
        if (!ch) break;
        len++;
        i++;
    }
    return len;
}
