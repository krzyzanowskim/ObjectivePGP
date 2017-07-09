//
//  PGPBigNum.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPBigNum.h"
#import "PGPBigNum+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPBigNum

- (instancetype)initWithBIGNUM:(BIGNUM *)bignumRef {
    NSAssert(bignumRef != nil, @"Unexpected nil");
    
    if ((self = [super init])) {
        _bignumRef = BN_dup(bignumRef);
    }
    return self;
}

- (int)bitsCount {
    return BN_num_bits(self.bignumRef);
}

- (int)bytesCount {
    return BN_num_bytes(self.bignumRef);
}

- (NSData *)data {
    let buflen = BN_num_bytes(self.bignumRef);
    let buf = calloc(buflen, 1);
    BN_bn2bin(self.bignumRef, buf);
    return [NSData dataWithBytes:buf length:buflen];
}

- (void)dealloc {
    BN_clear_free(_bignumRef);
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    return [[PGPBigNum alloc] initWithBIGNUM:BN_dup(self.bignumRef)];
}

@end

NS_ASSUME_NONNULL_END
