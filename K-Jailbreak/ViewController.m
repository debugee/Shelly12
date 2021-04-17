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

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (IBAction)jbBtnTapped:(UIButton *)sender {
    [jailbreak jb];
}

@end
