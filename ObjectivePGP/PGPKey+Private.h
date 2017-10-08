//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPKey.h"
#import "PGPPartialKey.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPKey ()

@property (nonatomic, nullable, copy, readwrite) PGPPartialKey *secretKey;
@property (nonatomic, nullable, copy, readwrite) PGPPartialKey *publicKey;

@end

NS_ASSUME_NONNULL_END
