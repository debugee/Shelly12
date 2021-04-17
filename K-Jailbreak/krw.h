//
//  krw.h
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/17.
//

#include <mach/mach.h>
#include <stdio.h>
#include <Foundation/Foundation.h>
#include <mach-o/loader.h>

#ifndef MIN
#    define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

//air1 12.4 offsets
#define KERNPROC 0xFFFFFFF0088E0A20
#define CS_BLOB_GEN_COUNT 0xFFFFFFF0087C2AB0

#define KERNEL_IMAGE_BASE 0xFFFFFFF007004000
#define PROC_P_LIST_LH_FIRST_OFF (0x0)
#define PROC_P_LIST_LE_PREV_OFF (0x8)
#define PROC_P_PID_OFF (0x60)
#define PROC_P_PID_UCRED_OFF (0xF8)
#define PROC_P_TEXTVP_OFF (0x230)
#define UCRED_CR_SVUID (0x20)
#define UCRED_CR_LABEL (0x78)
#define UCRED_CR_LABEL (0x78)
#define VNODE_V_NAME (0xB8)
#define VNODE_V_PARENT (0xC0)
#define VNODE_V_FLAG (0x54)
#define VNODE_V_MOUNT (0xD8)
#define VNODE_V_DATA (0xE0)
#define VNODE_VU_SPECINFO (0x78)
#define SPECINFO_SI_FLAGS (0x10)
#define MOUNT_MNT_DEVVP (0x980)
#define MOUNT_MNT_NEXT (0x0)
#define MOUNT_MNT_VNODELIST (0x40)
#define MOUNT_MNT_FLAG (0x70)
#define APFS_DATA_FLAG (0x31)
#define KSTRUCT_OFFSET_GET_TRAP_FOR_INDEX (0xB7)

#define AMFI_SLOT_OFF (0x8)
#define KSTRUCT_OFFSET_PROC_TASK (0x10)

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

CFDictionaryRef
OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

static task_t tfp0;
task_t getTFP0(void);
uint64_t getKBase(void);
uint64_t getProc(pid_t pid);
kern_return_t kread_buf(uint64_t addr, void *buf, size_t sz);
void *kread_buf_alloc(uint64_t addr, mach_vm_size_t read_sz);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);
unsigned long kstrlen(uint64_t string);
