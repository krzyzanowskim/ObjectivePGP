//
//  OpenPGPMPI.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Multiprecision integers (also called MPIs) are unsigned integers used
//  to hold large integers such as the ones used in cryptographic
//  calculations.

#import "PGPMPI.h"
#import <openssl/bn.h>

@interface PGPMPI ()
@end

@implementation PGPMPI {
    BIGNUM *_bn;
}

- (instancetype) initWithData:(NSData *)data atPosition:(NSUInteger)position
{
    if (self = [self init]) {
        UInt16 mpiBitsLength = 0;
        [data getBytes:&mpiBitsLength range:(NSRange){position,2}];
        NSUInteger mpiBytesLength = (CFSwapInt16BigToHost(mpiBitsLength) + 7) / 8;

        NSData *intdata = [data subdataWithRange:(NSRange){position + 2, mpiBytesLength}];
        _bn = BN_bin2bn(intdata.bytes, (int)intdata.length, NULL);

        // Additinal rule: The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
        _length = intdata.length + 2;
    }
    return self;
}

- (void)dealloc
{
    if (_bn != NULL) {
        BN_free(_bn);
    }
}

@end
