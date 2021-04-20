//
//  amfi.h
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/17.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface amfi : NSObject
+(void)resetEntitlements:(uint64_t)selfProc;
+(BOOL)grabEntitlements:(uint64_t)selfProc;
+(void)takeoverAmfid:(int)amfidPid;
+(void)platformize:(pid_t)pid;
+(uint8_t *)map_file_to_mem:(const char *)path;
+(BOOL)spawnAmfiDebilitate:(uint64_t)allProc;
@end

NS_ASSUME_NONNULL_END
