//
//  OpenPGPMPI.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Multiprecision integers (also called MPIs) are unsigned integers used
//  to hold large integers such as the ones used in cryptographic
//  calculations.

#import "PGPMPI.h"

@interface PGPMPI ()
@property (assign, readwrite) BIGNUM *bignumRef;
@property (assign, readwrite) NSUInteger packetLength;
@end

@implementation PGPMPI

- (instancetype) initWithData:(NSData *)dataToMPI
{
    if (self = [self init]) {
        _bignumRef = BN_bin2bn(dataToMPI.bytes, dataToMPI.length & INT_MAX, NULL);
        _packetLength = dataToMPI.length + 2;
    }
    return self;
}

// parse mpi "packet"
- (instancetype) initWithMPIData:(NSData *)mpiData atPosition:(NSUInteger)position
{
    if (self = [self init]) {
        UInt16 bitsBE = 0;
        [mpiData getBytes:&bitsBE range:(NSRange){position,2}];
        UInt16 bits = CFSwapInt16BigToHost(bitsBE);
        NSUInteger mpiBytesLength = (bits + 7) / 8;

        NSData *intdata = [mpiData subdataWithRange:(NSRange){position + 2, mpiBytesLength}];
        _bignumRef = BN_bin2bn(intdata.bytes, intdata.length & INT_MAX, NULL);
        // Additinal rule: The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
        _packetLength = intdata.length + 2;
    }
    return self;
}

- (NSData *)bodyData
{
    NSAssert(self.bignumRef, @"Missing bignumRef");
    
    if (!self.bignumRef)
        return nil;

    BIGNUM *mpi_BN = BN_dup(self.bignumRef);
    NSInteger mpi_BN_length = (BN_num_bits(mpi_BN) + 7) / 8;
    UInt8 *bn_bin = calloc(mpi_BN_length, sizeof(UInt8));
    NSUInteger len = BN_bn2bin(mpi_BN, bn_bin);
    BN_free(mpi_BN);

    NSData *data = [NSData dataWithBytes:bn_bin length:len];
    free(bn_bin);
    return data;
}

- (NSData *) exportMPI
{
    if (!self.bignumRef) {
        return nil;
    }

    NSMutableData *outData = [NSMutableData data];

    // length
    UInt16 bits = BN_num_bits(self.bignumRef);
    UInt16 bitsBE = CFSwapInt16HostToBig(bits);
    [outData appendBytes:&bitsBE length:2];
    
    // mpi
    UInt8 *buf = calloc(BN_num_bytes(self.bignumRef), sizeof(UInt8));
    UInt16 bytes = (bits + 7) / 8;
    BN_bn2bin(self.bignumRef, buf);
    [outData appendBytes:buf length:bytes];
    free(buf);

    return [outData copy];
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@, \"%@\", %@ bytes, total: %@ bytes", [super description], self.identifier, @(BN_num_bytes(self.bignumRef)), @(_packetLength)];
}

- (void)dealloc
{
    if (self.bignumRef != NULL) {
        BN_clear_free(self.bignumRef);
        _bignumRef = nil;
    }
}

@end
