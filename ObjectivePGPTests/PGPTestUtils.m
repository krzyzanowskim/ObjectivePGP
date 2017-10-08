//
//  PGPTestUtils.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 06/10/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTestUtils.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPTestUtils

+ (nullable NSBundle *)filesBundle {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"testfiles" ofType:@"bundle"];
    return [NSBundle bundleWithPath:path];
}

+ (NSString *)pathToBundledFile:(NSString *)fileName {
    NSBundle *bundle = self.filesBundle;
    return [bundle pathForResource:fileName.stringByDeletingPathExtension ofType:fileName.pathExtension];
}

+ (NSArray<PGPKey *> *)readKeysFromFile:(NSString *)fileName {
    NSString *path = [self pathToBundledFile:fileName];
    return [ObjectivePGP readKeysFromFile:path];
}


@end

NS_ASSUME_NONNULL_END
