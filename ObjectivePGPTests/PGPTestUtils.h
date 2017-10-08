//
//  ObjectivePGPTests
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPKey;

@interface PGPTestUtils : NSObject

+ (nullable NSBundle *)filesBundle;
+ (NSString *)pathToBundledFile:(NSString *)fileName;
+ (NSArray<PGPKey *> *)readKeysFromFile:(NSString *)fileName;

@end

NS_ASSUME_NONNULL_END
