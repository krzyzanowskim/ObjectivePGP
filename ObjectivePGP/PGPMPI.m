//
//  OpenPGPMPI.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Multiprecision integers (also called MPIArray) are unsigned integers used
//  to hold large integers such as the ones used in cryptographic
//  calculations.

#import "PGPMPI.h"
#import "PGPBigNum+Private.h"
#import "PGPLogging.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"
#import <openssl/bn.h>

NS_ASSUME_NONNULL_BEGIN

NSString * const PGPMPI_N = @"N";
NSString * const PGPMPI_E = @"E";
NSString * const PGPMPI_P = @"P";
NSString * const PGPMPI_G = @"G";
NSString * const PGPMPI_Q = @"Q";
NSString * const PGPMPI_D = @"D";
NSString * const PGPMPI_U = @"U";
NSString * const PGPMPI_X = @"X";
NSString * const PGPMPI_R = @"R";
NSString * const PGPMPI_S = @"S";
NSString * const PGPMPI_Y = @"Y";
NSString * const PGPMPI_M = @"M";

@interface PGPMPI ()

@property (nonatomic, readwrite) PGPBigNum *bigNum;
@property (nonatomic, readwrite) NSUInteger packetLength;

@end

@implementation PGPMPI

- (instancetype)initWithData:(NSData *)dataToMPI identifier:(NSString *)identifier {
    if ((self = [super init])) {
        _bigNum = [[PGPBigNum alloc] initWithBIGNUM:BN_bin2bn(dataToMPI.bytes, dataToMPI.length & INT_MAX, NULL)];
        _packetLength = dataToMPI.length + 2;
        _identifier = [identifier copy];
    }
    return self;
}

- (instancetype)initWithBigNum:(PGPBigNum *)bigNum identifier:(NSString *)identifier {
    return (self = [self initWithData:bigNum.data identifier:identifier]);
}

// parse mpi "packet"
- (instancetype)initWithMPIData:(NSData *)mpiData identifier:(NSString *)identifier atPosition:(NSUInteger)position {
    UInt16 bitsBE = 0;
    [mpiData getBytes:&bitsBE range:(NSRange){position, 2}];
    UInt16 bits = CFSwapInt16BigToHost(bitsBE);
    NSUInteger mpiBytesLength = (bits + 7) / 8;

    let intData = [mpiData subdataWithRange:(NSRange){position + 2, mpiBytesLength}];
    return (self = [self initWithData:intData identifier:identifier]);
}

- (nullable NSData *)bodyData {
    if (!self.bigNum) {
        PGPLogDebug(@"Missing bignum");
        return nil;
    }

    BIGNUM *mpi_BN = BN_dup(self.bigNum.bignumRef);
    NSInteger mpi_BN_length = (BN_num_bits(mpi_BN) + 7) / 8;
    UInt8 *bn_bin = calloc(mpi_BN_length, sizeof(UInt8));
    NSUInteger len = BN_bn2bin(mpi_BN, bn_bin);
    BN_clear_free(mpi_BN);

    NSData *data = [NSData dataWithBytes:bn_bin length:len];
    free(bn_bin);
    return data;
}

- (nullable NSData *)exportMPI {
    if (!self.bigNum) {
        return nil;
    }

    let outData = [NSMutableData data];

    // length
    UInt16 bits = (UInt16)BN_num_bits(self.bigNum.bignumRef);
    UInt16 bitsBE = CFSwapInt16HostToBig(bits);
    [outData appendBytes:&bitsBE length:2];

    // mpi
    UInt8 *buf = calloc(BN_num_bytes(self.bigNum.bignumRef), sizeof(UInt8));
    pgp_defer { free(buf); };
    UInt16 bytes = (bits + 7) / 8;
    BN_bn2bin(self.bigNum.bignumRef, buf);
    [outData appendBytes:buf length:bytes];

    return outData;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, \"%@\", %@ bytes, total: %@ bytes", [super description], self.identifier, @(self.bigNum.bytesCount), @(self.packetLength)];
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let copy = PGPCast([[self.class allocWithZone:zone] initWithBigNum:self.bigNum identifier:self.identifier], PGPMPI);
    copy.packetLength = self.packetLength;
    return copy;
}

@end

NS_ASSUME_NONNULL_END
