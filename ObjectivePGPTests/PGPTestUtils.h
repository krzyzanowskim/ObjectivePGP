//
//  PGPTestUtils.h
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 06/10/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPKey;

@interface PGPTestUtils : NSObject

+ (nullable NSBundle *)filesBundle;
+ (NSString *)pathToBundledFile:(NSString *)fileName;
+ (NSArray<PGPKey *> *)keysFromFile:(NSString *)fileName;

@end

NS_ASSUME_NONNULL_END
