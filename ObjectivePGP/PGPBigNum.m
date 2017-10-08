//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPBigNum.h"
#import "PGPBigNum+Private.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPBigNum

- (instancetype)initWithBIGNUM:(BIGNUM *)bignumRef {
    NSParameterAssert(bignumRef);
    
    if ((self = [super init])) {
        _bignumRef = BN_dup(bignumRef);
    }
    return self;
}

- (unsigned int)bitsCount {
    return BN_num_bits(self.bignumRef);
}

- (unsigned int)bytesCount {
    return BN_num_bytes(self.bignumRef);
}

- (NSData *)data {
    let buflen = self.bytesCount;
    let buf = calloc(buflen, 1);
    pgp_defer { if (buf) { free(buf); } };
    BN_bn2bin(self.bignumRef, buf);
    return [NSData dataWithBytes:buf length:buflen];
}

- (void)dealloc {
    BN_clear_free(_bignumRef);
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    return [[self.class allocWithZone:zone] initWithBIGNUM:BN_dup(self.bignumRef)];
}

@end

NS_ASSUME_NONNULL_END
