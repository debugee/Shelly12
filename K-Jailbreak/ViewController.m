//
//  ViewController.m
//  K-Jailbreak
//
//  Created by xsf1re on 2021/04/16.
//

#import "ViewController.h"
#import "jailbreak.h"

@interface ViewController ()
@end

@implementation ViewController

static ViewController* sharedInstance = nil;

+ (instancetype)sharedInstance {
    return sharedInstance;
}


- (void)viewDidLoad {
    [super viewDidLoad];
    sharedInstance = self;
    // Do any additional setup after loading the view.
    [self.LogView setText:@"Hello, K-Jailbreak!\n"];
    [self.LogView insertText:@"NOTE: It only works on iPad Air 1st Gen with iOS 12.4!\n"];
}

- (IBAction)jbBtnTapped:(UIButton *)sender {
    [jailbreak jb];
}

@end
