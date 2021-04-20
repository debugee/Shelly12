//
//  bootstrap.h
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/18.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface bootstrap : NSObject
+(void)bootstrapDevice;
+(int)runCommand:(const char*)cmd;
@end

NS_ASSUME_NONNULL_END
