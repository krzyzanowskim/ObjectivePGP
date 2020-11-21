//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPKeyring.h>
#import <ObjectivePGP/PGPKey.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPKeyring ()

// Private
+ (nullable PGPKey *)findKeyWithKeyID:(PGPKeyID *)searchKeyID in:(NSArray<PGPKey *> *)keys;
+ (NSArray<PGPKey *> *)addOrUpdatePartialKey:(nullable PGPPartialKey *)key inContainer:(NSArray<PGPKey *> *)keys;

@end

NS_ASSUME_NONNULL_END

