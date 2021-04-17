//
//  remount.h
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/17.
//

#import <Foundation/Foundation.h>
#include <sys/time.h>

NS_ASSUME_NONNULL_BEGIN

struct hfs_mount_args {
    char    *fspec;            /* block special device to mount */
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t hfs_encoding;    /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

@interface remount : NSObject
+(int)remount:(uint64_t)launchd_proc;
+(uint64_t)findRootVnode:(uint64_t)launchd_proc;
+(BOOL)restore_rootfs;
@end

NS_ASSUME_NONNULL_END
