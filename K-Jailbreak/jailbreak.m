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
#include "bootstrap.h"
#include <spawn.h>


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
    uint64_t kslide = kbase - KERNEL_IMAGE_BASE;
    NSLog(@"kernel base: 0x%llx\n", kbase);
    NSLog(@"kernel slide: 0x%llx\n", kslide);
    
    //  Stage 3 - Get root and grab kernel credentials.
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
    
    //  Stage 4 - Escape Sandbox
    if(!escapeSandboxForProcess(getpid()))
    {
        NSLog(@"Failed to escape sandbox\n");
        return;
    }
    
    //  Stage 5 - Set tfp0 to hsp4
    if(!SetHSP4(tfp0))
    {
        NSLog(@"Failed to set tfp0 to hsp4\n");
        return;
    }
    
    //  Stage 6.1 - Remount RootFS
    if(![remount remount:getProc(1)])
    {
        NSLog(@"Failed to remount rootfs!\n");
        return;
    }
    //  Stage 6.2 - Restore RootFS
//    if(![remount restore_rootfs])
//    {
//        NSLog(@"Failed to restore rootfs!\n");
//        return;
//    }
    
    //  Stage 7 - Make executable
    [amfi platformize:getpid()];
    [amfi grabEntitlements:getProc(getpid())];
    [amfi takeoverAmfid:getPidByName("amfid")];
    
    //  Stage 8 - Extract bootstraps
    [bootstrap bootstrapDevice];
    
    //  Stage 9 - run amfidebilitate
    if(![amfi spawnAmfiDebilitate:(ALLPROC + kslide)])
    {
        NSLog(@"Failed to spawn AmfiDebilitate");
        return;
    }
    
    //  check if successfully run helloworld.
    int rv;
    pid_t pd;
    
    unlink("/.amfid_success");
    chmod("/odyssey/helloworld", 0755);
    const char *args_helloworld[] = {"helloworld", NULL};
    rv = posix_spawn(&pd, "/odyssey/helloworld", NULL, NULL, (char **)&args_helloworld, NULL);
    NSLog(@"posix ret: %d", rv);
    sleep(1);
    if(access("/.amfid_success", F_OK) != 0) {
        NSLog(@"amfid injection fail!");
        return;
    }
    NSLog(@"amfid injection success!");
    unlink("/.amfid_success");

    NSLog(@"K-Jailbreak End!");
}
@end
