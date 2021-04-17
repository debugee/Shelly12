//
//  remount.m
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/17.
//

#import "remount.h"
#include "krw.h"
#include <sys/attr.h>
#include <sys/snapshot.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <IOKit/IOKitLib.h>

char* mntpathSW;
char* mntpath;

@implementation remount
+(int)remount:(uint64_t)launchd_proc {
    mntpathSW = "/var/rootfsmnt";
    mntpath = strdup("/var/rootfsmnt");
    uint64_t rootvnode = [self findRootVnode:launchd_proc];
    NSLog(@"rootvnode: 0x%llx", rootvnode);
    if([self isRenameRequired]) {
        if(access(mntpathSW, F_OK) == 0) {
            remove(mntpathSW);
        }
        
        mkdir(mntpath, 0755);
        chown(mntpath, 0, 0);
        
        if([self isOTAMounted]) {
            NSLog(@"OTA update already mounted");
            return false;
        }
        
        uint64_t kernCreds = kread64(getProc(0) + PROC_P_PID_UCRED_OFF);
        uint64_t selfCreds = kread64(getProc(getpid()) + PROC_P_PID_UCRED_OFF);
        
        kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, kernCreds);
        
        char* bootSnapshot = [self find_boot_snapshot];
        if(!bootSnapshot
           || [self mountRealRootfs:rootvnode]) {
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        
        int fd = open("/var/rootfsmnt", O_RDONLY, 0);
        if(fd <= 0
           || fs_snapshot_revert(fd, bootSnapshot, 0) != 0) {
            NSLog(@"fs_snapshot_revert failed");
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        close(fd);
        
        unmount(mntpath, MNT_FORCE);
        
        if([self mountRealRootfs:rootvnode]) {
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        
        uint64_t newmnt = [self findNewMount:rootvnode];
        if(!newmnt) {
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        
        if(![self unsetSnapshotFlag:newmnt]) {
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        
        int fd2 = open("/var/rootfsmnt", O_RDONLY, 0);
        if(fd <= 0
           || fs_snapshot_rename(fd2, bootSnapshot, "orig-fs", 0) != 0) {
            NSLog(@"fs_snapshot_rename failed");
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        close(fd2);
        
        unmount(mntpath, 0);
        remove(mntpath);

        kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
        
        NSLog(@"Reboot!");
        sleep(5);
        reboot(0);
    } else {
        uint64_t vmount = kread64(rootvnode + VNODE_V_MOUNT);
        uint32_t vflag = kread32(vmount + MOUNT_MNT_FLAG) & ~(MNT_RDONLY);
        kwrite32(vmount + MOUNT_MNT_FLAG, vflag & ~(MNT_ROOTFS));
        
        char* dev_path = strdup("/dev/disk0s1s1");
        int retval = mount("apfs", "/", MNT_UPDATE, &dev_path);
        free(dev_path);
        
        kwrite32(vmount + MOUNT_MNT_FLAG, vflag | (MNT_NOSUID));
        return retval == 0;
    }
    return true;
}

+(uint64_t)findRootVnode:(uint64_t)launchd_proc {
    //  https://github.com/apple/darwin-xnu/blob/xnu-4903.270.47/bsd/sys/proc_internal.h#L194
    //  https://github.com/apple/darwin-xnu/blob/xnu-4903.270.47/bsd/sys/vnode_internal.h#L127
    
    uint64_t textvp = kread64(launchd_proc + PROC_P_TEXTVP_OFF);
    uint64_t nameptr = kread64(textvp + VNODE_V_NAME);
    char name[20];
    kread_buf(nameptr, &name, 20);  //  <- launchd;
    
    uint64_t sbin = kread64(textvp + VNODE_V_PARENT);
    nameptr = kread64(sbin + VNODE_V_NAME);
    kread_buf(nameptr, &name, 20);  //  <- sbin
    
    uint64_t rootvnode = kread64(sbin + VNODE_V_PARENT);
    nameptr = kread64(sbin + VNODE_V_NAME);
    kread_buf(nameptr, &name, 20);  //  <- / (ROOT)
    
    uint32_t flags = kread32(rootvnode + VNODE_V_FLAG);
    NSLog(@"flags: 0x%x", flags);
    
    return rootvnode;
}

+(BOOL)isRenameRequired {
    int fd = open("/", O_RDONLY, 0);
    struct attrlist alist;
    memset(&alist, 0, sizeof(alist));
    
    alist.commonattr = ATTR_BULK_REQUIRED;
    
    char abuf[2048];
    int count = fs_snapshot_list(fd, &alist, &abuf[0], 2048, 0);
    NSLog(@"snapshot count: %d", count);
    close(fd);
    
    return count == -1;
}

+(BOOL)isOTAMounted {
    const char* path = strdup("/var/MobileSoftwareUpdate/mnt1");
    
    struct stat buffer;
    if (lstat(path, &buffer) != 0) {
        return false;
    }
    
    if((buffer.st_mode & S_IFMT) != S_IFDIR) {
        return false;
    }
    
    char* cwd = getcwd(nil, 0);
    chdir(path);
    
    struct stat p_buf;
    lstat("..", &p_buf);
    
    if(cwd) {
        chdir(cwd);
        free(cwd);
    }
    
    return buffer.st_dev != p_buf.st_dev || buffer.st_ino == p_buf.st_ino;
}

+(char *)find_boot_snapshot {
    io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    CFDataRef data = IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    if(!data)
        return nil;
    IOObjectRelease(chosen);
    
    CFIndex length = CFDataGetLength(data) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int i = 0;
    for (i = 0; i<(int)CFDataGetLength(data); i++) {
        sprintf(manifestHash+i*2, "%02X", CFDataGetBytePtr(data)[i]);
    }
    manifestHash[i*2] = 0;
    
    CFRelease(data);

    char* systemSnapshot = malloc(sizeof(char) * 64);
    strcpy(systemSnapshot, "com.apple.os.update-");
    strcat(systemSnapshot, manifestHash);
    
    return systemSnapshot;
}

+(int)mountRealRootfs:(uint64_t)rootvnode {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/vnode_internal.h#L127
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/mount_internal.h#L107
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/miscfs/specfs/specdev.h#L77
    uint64_t vmount = kread64(rootvnode + VNODE_V_MOUNT);
    uint64_t dev = kread64(vmount + MOUNT_MNT_DEVVP);
    
    uint64_t nameptr = kread64(dev + VNODE_V_NAME);
    char name[20];
    kread_buf(nameptr, &name, 20);   //  <- disk0s1s1
    NSLog(@"found dev vnode name: %s", name);
    
    uint64_t specinfo = kread64(dev + VNODE_VU_SPECINFO);
    uint32_t flags = kread32(specinfo + SPECINFO_SI_FLAGS);
    NSLog(@"found dev flags: 0x%x", flags);
    
    kwrite32(specinfo + SPECINFO_SI_FLAGS, 0);
    char* fspec = strdup("/dev/disk0s1s1");
    
    struct hfs_mount_args mntargs;
    mntargs.fspec = fspec;
    mntargs.hfs_mask = 1;
    gettimeofday(nil, &mntargs.hfs_timezone);
    
    int retval = mount("apfs", mntpath, 0, &mntargs);
    free(fspec);
    
    NSLog(@"mount completed with status: %d", retval);
    
    return retval;
}

+(uint64_t)findNewMount:(uint64_t)rootvnode {
    uint64_t vmount = kread64(rootvnode + VNODE_V_MOUNT);
    
    vmount = kread64(vmount + MOUNT_MNT_NEXT);
    while (vmount != 0) {
        uint64_t dev = kread64(vmount + MOUNT_MNT_DEVVP);
        if(dev != 0) {
            uint64_t nameptr = kread64(dev + VNODE_V_NAME);
            char name[20];
            kread_buf(nameptr, &name, 20);
            char* devName = name;
            NSLog(@"found dev vnode name: %s", devName);
            
            if(strcmp(devName, "disk0s1s1") == 0) {
                return vmount;
            }
        }
        vmount = kread64(vmount + MOUNT_MNT_NEXT);
    }
    return 0;
}

+(BOOL)unsetSnapshotFlag:(uint64_t)newmnt {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/mount_internal.h#L107
    uint64_t dev = kread64(newmnt + MOUNT_MNT_DEVVP);
    uint64_t nameptr = kread64(dev + VNODE_V_NAME);
    char name[20];
    kread_buf(nameptr, &name, 20);
    NSLog(@"found dev vnode name: %s", name);
    
    uint64_t specinfo = kread64(dev + VNODE_VU_SPECINFO);
    uint64_t flags = kread32(specinfo + SPECINFO_SI_FLAGS);
    NSLog(@"found dev flags: 0x%llx", flags);
    
    uint64_t vnodelist = kread64(newmnt + MOUNT_MNT_VNODELIST);
    while (vnodelist != 0) {
        NSLog(@"vnodelist: 0x%llx", vnodelist);
        uint64_t nameptr = kread64(vnodelist + VNODE_V_NAME);
        unsigned long len = kstrlen(nameptr);
        char name[len];
        kread_buf(nameptr, &name, len);
        
        char* vnodeName = name;
        NSLog(@"found vnode name: %s", vnodeName);
        
        if(strstr(vnodeName, "com.apple.os.update-") != NULL) {
            uint64_t vdata = kread64(vnodelist + VNODE_V_DATA);
            uint32_t flag = kread32(vdata + APFS_DATA_FLAG);
            NSLog(@"found apfs flag: 0x%x", flag);
            
            if ((flag & 0x40) != 0) {
                NSLog(@"would unset the flag here to: 0x%x", flag & ~0x40);
                kwrite32(vdata + APFS_DATA_FLAG, flag & ~0x40);
                return true;
            }
        }
        usleep(1000);
        vnodelist = kread64(vnodelist + 0x20);
    }
    return false;
}

+(BOOL)restore_rootfs {
    if(![self isRenameRequired]) {
        char* bootSnapshot = [self find_boot_snapshot];
        if(!bootSnapshot)
            return false;
        
        remove("/var/cache");
        remove("/var/lib");
        
        uint64_t kernCreds = kread64(getProc(0) + PROC_P_PID_UCRED_OFF);
        uint64_t selfCreds = kread64(getProc(getpid()) + PROC_P_PID_UCRED_OFF);
        
        kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, kernCreds);
        
        int fd = open("/", O_RDONLY, 0);
        if(fd <= 0
           || fs_snapshot_rename(fd, "orig-fs", bootSnapshot, 0) != 0) {
            NSLog(@"fs_snapshot_rename failed");
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        
        if(fs_snapshot_revert(fd, bootSnapshot, 0) != 0) {
            NSLog(@"fs_snapshot_revert failed");
            kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
            return false;
        }
        close(fd);
        
        kwrite64(getProc(getpid()) + PROC_P_PID_UCRED_OFF, selfCreds);
        NSLog(@"Reboot!");
        sleep(5);
        reboot(0);
    } else {
        NSLog(@"rootfs restore not required");
    }
    return true;
}
@end
