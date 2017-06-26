//
//  PGPBigNum.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPBigNum.h"
#import <openssl/bn.h>
#import <Foundation/Foundation.h>

@interface PGPBigNum ()

@property (nonatomic, readonly) BIGNUM *bignumRef;

- (instancetype)initWithBIGNUM:(BIGNUM *)bignumRef;

@end

