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
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPBigNum

- (instancetype)initWithBIGNUM:(BIGNUM *)bignumRef {
    NSParameterAssert(bignumRef);
    
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
    let buflen = (size_t)self.bytesCount;
    let buf = calloc(buflen, 1);
    pgp_defer { if (buf) { free(buf); } };
    BN_bn2bin(self.bignumRef, buf);
    return [NSData dataWithBytes:buf length:buflen];
}

- (void)dealloc {
    BN_clear_free(_bignumRef);
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToBigNum:other];
    }
    return NO;
}

- (BOOL)isEqualToBigNum:(PGPBigNum *)other {
    return BN_cmp(self.bignumRef, other.bignumRef) == 0;
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + self.data.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    return [[self.class allocWithZone:zone] initWithBIGNUM:BN_dup(self.bignumRef)];
}

@end

NS_ASSUME_NONNULL_END
