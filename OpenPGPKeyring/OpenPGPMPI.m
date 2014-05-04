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

#import "OpenPGPMPI.h"
#import <openssl/bn.h>

@interface OpenPGPMPI ()
@end

@implementation OpenPGPMPI {
    BIGNUM *_bn;
}

- (instancetype) initWithData:(NSData *)data atPosition:(NSUInteger)position
{
    if (self = [self init]) {
        UInt16 mpiLength = 0;
        [data getBytes:&mpiLength range:(NSRange){position,2}];
        mpiLength = (CFSwapInt16BigToHost(mpiLength) + 7) / 8;

        NSData *intdata = [data subdataWithRange:(NSRange){position + 2, mpiLength}];
        _bn = BN_bin2bn(intdata.bytes, intdata.length, NULL);

        // Additinal rule: The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
        _length = mpiLength + 2;
    }
    return self;
}

- (void)dealloc
{
    BN_free(_bn);
}

@end
