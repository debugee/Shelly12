//
//  bootstrap.m
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/18.
//

#import "bootstrap.h"
#include <sys/stat.h>
#include <spawn.h>
#include <dirent.h>

extern char **environ;

#define moveFile(copyFrom, moveTo) [[NSFileManager defaultManager] moveItemAtPath:@(copyFrom) toPath:@(moveTo) error:&nil];

#define fileExists(file) [[NSFileManager defaultManager] fileExistsAtPath:@(file)]

#define removeFile(file) [[NSFileManager defaultManager] removeItemAtPath:@(file) error:nil];

#define in_bundle(obj) strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@obj] UTF8String])

@implementation bootstrap
+(void)bootstrapDevice {
    removeFile("/odyssey");
    
    mkdir("/odyssey", 0755);
    chown("/odyssey", 0, 0);
    
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithUTF8String:in_bundle("tar")] toPath:@"/odyssey/tar" error:nil];
    chmod("/odyssey/tar", 0755);
    
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithUTF8String:in_bundle("helloworld")] toPath:@"/odyssey/helloworld" error:nil];
    
    [self untarBaseBinaries];
}

+(BOOL)untarBaseBinaries {
    pid_t pid;
    const char* args[] = {"tar", "--preserve-permissions", "-xkf", in_bundle("basebinaries.tar"), "-C", "/odyssey", NULL};
    
    int status = posix_spawn(&pid, "/odyssey/tar", NULL, NULL, (char **)&args, environ);
    if(status == 0) {
        if(waitpid(pid, &status, 0) == -1) {
            NSLog(@"waitpid error");
        }
    }
    else {
        NSLog(@"posix_spawn error: %d", status);
    }
    
    return status == 0;
}

+(BOOL)untarBootstrap {
    pid_t pid;
    const char* args[] = {"tar", "--preserve-permissions", "-xkf", in_bundle("bootstrap.tar"), "-C", "/", NULL};
    
    int status = posix_spawn(&pid, "/odyssey/tar", NULL, NULL, (char **)&args, environ);
    if(status == 0) {
        if(waitpid(pid, &status, 0) == -1) {
            NSLog(@"waitpid error");
        }
    }
    else {
        NSLog(@"posix_spawn error: %d", status);
    }
    
    return status == 0;
}

+(int)runCommand:(const char*)cmd {
    pid_t pid;
    const char* args[] = {"sh", "-c", cmd, NULL};
    
    int status = posix_spawn(&pid, "/bin/sh", NULL, NULL, (char **)&args, environ);
    if(status == 0) {
        if(waitpid(pid, &status, 0) == -1) {
            NSLog(@"waitpid error");
        }
    }
    else {
        NSLog(@"posix_spawn error: %d", status);
    }
    
    return status;
}
@end


