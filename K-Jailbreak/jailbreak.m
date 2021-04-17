//
//  jailbreak.m
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/16.
//

#import "jailbreak.h"
#include "exploit.h"
#include "krw.h"
#include "remount.h"
#include "amfi.h"
#include <sys/stat.h>

@implementation jailbreak
+(void)jb {
    //  Stage 1 - Get kernel R/W privileges;
    mach_port_t tfp0 = getTFP0();
    if(tfp0 == MACH_PORT_NULL)
    {
        NSLog(@"Failed to get tfp0");
        return;
    }
    NSLog(@"tfp0: 0x%x", tfp0);
    
    //  Stage 2 - Get kernel base and kernel slide;
    uint64_t kbase = getKBase();
    if(!kbase)
    {
        NSLog(@"Failed to get kbase\n");
        return;
    }
    NSLog(@"kernel base: 0x%llx\n", kbase);
    NSLog(@"kernel slide: 0x%llx\n", kbase - KERNEL_IMAGE_BASE);
    
    //  Stage 3 - Get root
    uint64_t kernProc = getProc(0);
    uint64_t selfProc = getProc(getpid());
    
    uint64_t kernCreds = kread64(kernProc + PROC_P_PID_UCRED_OFF);
    uint64_t selfCreds = kread64(selfProc + PROC_P_PID_UCRED_OFF);
    
    uint64_t ourLabel = kread64(selfCreds + UCRED_CR_LABEL);
    kwrite64(selfCreds + UCRED_CR_LABEL, kread64(kernCreds + UCRED_CR_LABEL));
    kwrite32(selfCreds + UCRED_CR_SVUID, 0);
    
    setuid(0);
    setuid(0);
    kwrite64(selfCreds + UCRED_CR_LABEL, ourLabel);
    if(getuid() != 0)
    {
        NSLog(@"Failed to get root\n");
        return;
    }
    NSLog(@"uid: %d\n", getuid());
    
    //  Stage 4 - Remount RootFS
    if(![remount remount:getProc(1)])
    {
        NSLog(@"Failed to remount rootfs!\n");
        return;
    }
    //  Stage 4.1 - Restore RootFS
//    if(![remount restore_rootfs])
//    {
//        NSLog(@"Failed to restore rootfs!\n");
//        return;
//    }
    
    //  Stage 5 - Make executable
    remove("/chimera");
    mkdir("/chimera", 0755);
    chown("/chimera", 0, 0);
    
    mkdir("/chimera/cstmp/", 0700);
    chown("/chimera/cstmp/", 0, 0);
    
    unlink("/chimera/pspawn_payload.dylib");
    unlink("/usr/lib/pspawn_payload-stg2.dylib");
    
    [amfi platformize:getpid()];
    
    if(![amfi grabEntitlements:selfProc])
        return;
    
    int amfidPid = kread32(getProcByName("amfid") + PROC_P_PID_OFF);
    [amfi takeoverAmfid:amfidPid];
    
    
}
@end
