//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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

PGPMPIdentifier const PGPMPIdentifierN = @"N";
PGPMPIdentifier const PGPMPIdentifierE = @"E";
PGPMPIdentifier const PGPMPIdentifierP = @"P"; // Prime
PGPMPIdentifier const PGPMPIdentifierG = @"G"; // Generator
PGPMPIdentifier const PGPMPIdentifierQ = @"Q"; // ECC public key
PGPMPIdentifier const PGPMPIdentifierD = @"D"; // ECC secret key
PGPMPIdentifier const PGPMPIdentifierU = @"U";
PGPMPIdentifier const PGPMPIdentifierX = @"X"; // secret
PGPMPIdentifier const PGPMPIdentifierR = @"R";
PGPMPIdentifier const PGPMPIdentifierS = @"S";
PGPMPIdentifier const PGPMPIdentifierY = @"Y"; // public key. For Elgamal public key value y (= g**x mod p where x is secret).
PGPMPIdentifier const PGPMPIdentifierM = @"M";
PGPMPIdentifier const PGPMPIdentifierV = @"V"; // EC public point
//EC public key R
//EC shared point S

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

    let mpi_BN = BN_dup(self.bigNum.bignumRef);
    let mpi_BN_length = (BN_num_bits(mpi_BN) + 7) / 8;
    UInt8 *bn_bin = calloc((size_t)mpi_BN_length, sizeof(UInt8));
    let len = (NSUInteger)BN_bn2bin(mpi_BN, bn_bin);
    BN_clear_free(mpi_BN);

    let data = [NSData dataWithBytes:bn_bin length:len];
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
    UInt8 *buf = calloc((size_t)BN_num_bytes(self.bigNum.bignumRef), sizeof(UInt8));
    pgp_defer { free(buf); };
    UInt16 bytes = (bits + 7) / 8;
    BN_bn2bin(self.bigNum.bignumRef, buf);
    [outData appendBytes:buf length:bytes];

    return outData;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, \"%@\", %@ bytes, total: %@ bytes", [super description], self.identifier, @(self.bigNum.bytesCount), @(self.packetLength)];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToMPI:other];
    }
    return NO;
}

- (BOOL)isEqualToMPI:(PGPMPI *)other {
    return PGPEqualObjects(self.identifier, other.identifier) && PGPEqualObjects(self.bigNum, other.bigNum);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + self.identifier.hash;
    result = prime * result + self.bigNum.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([[self.class allocWithZone:zone] initWithBigNum:self.bigNum identifier:self.identifier], PGPMPI);
    duplicate.packetLength = self.packetLength;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
