//
//  PGPTestUtils.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 06/10/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTestUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPTestUtils

+ (nullable NSBundle *)filesBundle {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"testfiles" ofType:@"bundle"];
    return [NSBundle bundleWithPath:path];
}

@end

NS_ASSUME_NONNULL_END
