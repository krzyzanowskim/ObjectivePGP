//
//  PGPBigNum.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPBigNum.h"
#import "PGPBigNum+Private.h"

@implementation PGPBigNum

- (instancetype)initWithBIGNUM:(BIGNUM *)bignumRef {
    if ((self = [super init])) {
        _bignumRef = bignumRef;
    }
    return self;
}

- (int)bitsCount {
    return BN_num_bits(self.bignumRef);
}

- (int)bytesCount {
    return BN_num_bytes(self.bignumRef);
}

- (void)dealloc {
    BN_clear_free(self.bignumRef);
}

@end
