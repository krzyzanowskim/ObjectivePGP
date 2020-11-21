//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPBigNum.h>
#import <ObjectivePGP/PGPMacros.h>
#import <openssl/bn.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPBigNum ()

@property (nonatomic, readonly) BIGNUM *bignumRef;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithBIGNUM:(BIGNUM *)bignumRef;

@end

NS_ASSUME_NONNULL_END
