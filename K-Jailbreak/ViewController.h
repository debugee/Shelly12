//
//  ViewController.h
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/16.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

@property (strong, nonatomic) IBOutlet UITextView *LogView;

+ (instancetype)sharedInstance;
@end

