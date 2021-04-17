//
//  amfi.m
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/17.
//

#import "amfi.h"
#include <spawn.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include "krw.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>
#include <pthread/pthread.h>

static bool has_entitlements = false;
extern char**environ;
static pid_t sysdiagnose_pid = 0;
static uint64_t selfEnts = 0;
static uint64_t sysdiagnoseEnts = 0;
static mach_port_t amfid_task_port = MACH_PORT_NULL;
static mach_port_t exceptionPort = MACH_PORT_NULL;

@implementation amfi
+(BOOL)grabEntitlements:(uint64_t)selfProc {
    if(has_entitlements)
        return false;
    
    posix_spawnattr_t attrp;
    posix_spawnattr_init(&attrp);
    posix_spawnattr_setflags(&attrp, POSIX_SPAWN_START_SUSPENDED);
    
    pid_t pid;
    const char *argv[] = {"spindump", NULL};
    int retVal = posix_spawn(&pid, "/usr/sbin/spindump", NULL, &attrp, (char* const*)argv, environ);
    if(retVal < 0)
        return false;
    sysdiagnose_pid = pid;
    
    uint64_t sysdiagnose_proc = getProc(pid);
    if(!sysdiagnose_proc)
        return false;
    
    uint64_t selfCreds = kread64(selfProc + PROC_P_PID_UCRED_OFF);
    uint64_t sysdiagnoseCreds = kread64(sysdiagnose_proc + PROC_P_PID_UCRED_OFF);
    
    selfEnts = kread64(kread64(selfCreds + UCRED_CR_LABEL) + AMFI_SLOT_OFF);
    sysdiagnoseEnts = kread64(kread64(sysdiagnoseCreds + UCRED_CR_LABEL) + AMFI_SLOT_OFF);
    
    kwrite64(kread64(selfCreds + UCRED_CR_LABEL) + AMFI_SLOT_OFF, sysdiagnoseEnts);
    
    has_entitlements = true;
    return true;
}

+(void)takeoverAmfid:(int)amfidPid {
    if(!has_entitlements)
        return;
    
    kern_return_t retVal = task_for_pid(mach_task_self(), amfidPid, &amfid_task_port);
    if(retVal != 0) {
        NSLog(@"Unable to get amfid task: %s", mach_error_string(retVal));
        return;
    }
    NSLog(@"Got amfid task port: 0x%x", amfid_task_port);
    
    //    AMFID_MISValidateSignatureAndCopyInfo;
    uint64_t loadAddress = [self loadAddr:amfid_task_port];
    NSLog(@"loadAddress: 0x%llx", loadAddress);
    
    retVal = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed mach_port_allocate: %s", mach_error_string(retVal));
        return;
    }
    
    retVal = mach_port_insert_right(mach_task_self(), exceptionPort, exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed mach_port_insert_right: %s", mach_error_string(retVal));
        return;
    }
    
    retVal = task_set_exception_ports(amfid_task_port, EXC_MASK_BAD_ACCESS, exceptionPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed task_set_exception_ports: %s", mach_error_string(retVal));
        return;
    }
    
    //  https://github.com/GeoSn0w/Blizzard-Jailbreak/blob/2b1193e29f1c8b73ff1d1f09ca7760bfe208553e/Exploits/FreeTheSandbox/ios13_kernel_universal.c#L2909
    uint8_t *amfid_fdata = [self map_file_to_mem:"/usr/libexec/amfid"];
    uint64_t patchOffset = [self find_amfid_OFFSET_MISValidate_symbol:amfid_fdata];
    NSLog(@"_MISValidateSignatureAndCopyInfo offset: 0x%llx", patchOffset);
    munmap(amfid_fdata, amfid_fsize);
    
    retVal = vm_protect(amfid_task_port, mach_vm_trunc_page(loadAddress + patchOffset), vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed vm_protect: %s", mach_error_string(retVal));
    }
    
    uint64_t patchAddr = loadAddress + patchOffset;
    [self amfidWrite64:patchAddr data:0x12345];
    
    sleep(5);
    reboot(0);
}

+(void)amfidWrite64:(uint64_t)addr data:(uint64_t)data {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&data, (mach_msg_type_number_t)sizeof(uint64_t));
    if(err != KERN_SUCCESS) {
        NSLog(@"failed mach_vm_write: %s", mach_error_string(err));
    }
}


+(uint64_t)loadAddr:(mach_port_t)port {
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL;
    
    mach_vm_address_t first_addr = 0;
    mach_vm_size_t first_size = 0x1000;
    
    struct vm_region_basic_info_64 region = {0};
    
    kern_return_t err = mach_vm_region(port, &first_addr, &first_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &region_count, &object_name);
    if (err != KERN_SUCCESS) {
        NSLog(@"failed to get the region: %s", mach_error_string(err));
        return 0;
    }
    
    return first_addr;
}

+(void)platformize:(pid_t)pid {
    //  https://github.com/apple/darwin-xnu/blob/xnu-4903.270.47/bsd/sys/proc_internal.h#L194
    //  https://github.com/apple/darwin-xnu/blob/main/osfmk/kern/task.h#L264
    
    if (!pid) return;
    
    uint64_t proc = getProc(pid);
    uint64_t task = kread64(proc + PROC_TASK);
    
    uint32_t t_flags = kread32(task + TASK_T_FLAGS);
    kwrite32(task+TASK_T_FLAGS, t_flags | TF_PLATFORM);
    
    uint32_t csflags = kread32(proc + PROC_P_CSFLAGS);
    csflags = csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    csflags &= ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kwrite32(proc + PROC_P_CSFLAGS, csflags);
}

size_t amfid_fsize = 0;
+(uint8_t *)map_file_to_mem:(const char *)path{
    struct stat fstat = {0};
    stat(path, &fstat);
    amfid_fsize = fstat.st_size;
    
    int fd = open(path, O_RDONLY);
    uint8_t *mapping_mem = mmap(NULL, mach_vm_round_page(amfid_fsize), PROT_READ, MAP_SHARED, fd, 0);
    if((int)mapping_mem == -1){
        NSLog(@"Error in map_file_to_mem(): mmap() == -1\n");
        return 0;
    }
    return mapping_mem;
}

+(uint64_t)find_amfid_OFFSET_MISValidate_symbol:(uint8_t*)amfid_macho {
    uint32_t MISValidate_symIndex = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)amfid_macho;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)(mh + 1);
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
                
                for(int i =0;i<nsyms;i++){
                    struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                    char *def_str = NULL;
                    if(nn->n_type==0x1){
                        // 0x1 indicates external function
                        def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                        if(!strcmp(def_str, "_MISValidateSignatureAndCopyInfo")){
                            break;
                        }
                    }
                    if(i!=0 && i!=1){ // Two at beginning are local symbols, they don't count
                        MISValidate_symIndex++;
                    }
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    if(MISValidate_symIndex == 0){
        printf("Error in find_amfid_OFFSET_MISValidate_symbol(): MISValidate_symIndex == 0\n");
        return 0;
    }
    
    const struct section_64 *sect_info = NULL;
    const char *_segment = "__DATA", *_section = "__la_symbol_ptr";
    sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment, _section);
    
    if(!sect_info){
        printf("Error in find_amfid_OFFSET_MISValidate_symbol(): if(!sect_info)\n");
        return 0;
    }
    
    return sect_info->offset + (MISValidate_symIndex * 0x8);
}
@end
