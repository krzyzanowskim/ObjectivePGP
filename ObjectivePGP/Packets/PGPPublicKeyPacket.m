//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPublicKeyPacket+Private.h"
#import "PGPPacket+Private.h"
#import "NSData+PGPUtils.h"
#import "NSArray+PGPUtils.h"
#import "PGPCurveOID.h"
#import "PGPMPI.h"
#import "PGPRSA.h"
#import "PGPElgamal.h"
#import "PGPTypes.h"
#import "PGPFoundation.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPMacros+Private.h"
#import "PGPLogging.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <objc/runtime.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPublicKeyPacket

- (instancetype)init {
    if ((self = [super init])) {
        _version = 0x04;
        _createDate = NSDate.date;
        _publicMPIs = [NSArray<PGPMPI *> array];
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPPublicKeyPacketTag;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", [super description], self.keyID];
}

- (nullable PGPMPI *)publicMPI:(NSString *)identifier {
    let mpi = [[self.publicMPIs pgp_objectsPassingTest:^BOOL(PGPMPI *obj, BOOL *stop) {
        *stop = PGPEqualObjects(obj.identifier, identifier);
        return *stop;
    }] firstObject];

    return mpi;
}

#pragma mark - Properties

- (NSUInteger)keySize {
    //TODO: Elgamal, how about elgamal?
    let mpi = [self publicMPI:PGPMPI_N];
    return (mpi.bigNum.bitsCount + 7) / 8; // ks;
}

/**
 *  12.2.  Key IDs and Fingerprints
 *
 *  @return keyID
 */
- (PGPKeyID *)keyID {
    return [[PGPKeyID alloc] initWithFingerprint:self.fingerprint];
}

/**
 *  12.2.  Key IDs and Fingerprints
 *  Calculate fingerprint
 *
 *  @return Fingerprint data
 */
- (PGPFingerprint *)fingerprint {
    return [[PGPFingerprint alloc] initWithData:[self exportKeyPacketOldStyle]];
}

#pragma mark - Parse data

/**
 *  5.5.2.  Public-Key Packet Formats
 *
 *  @param packetBody Packet body
 */
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // A one-octet version number (2,3,4).
    [packetBody getBytes:&_version range:(NSRange){position, 1}];
    position = position + 1;

    NSAssert(self.version >= 3, @"Too old packet version");

    // A four-octet number denoting the time that the key was created.
    UInt32 timestamp = 0;
    [packetBody getBytes:&timestamp range:(NSRange){position, 4}];
    timestamp = CFSwapInt32BigToHost(timestamp);
    self.createDate = [NSDate dateWithTimeIntervalSince1970:timestamp];
    position = position + 4;

    // V3 keys are deprecated; an implementation MUST NOT generate a V3 key, but MAY accept it.
    if (self.version == 0x03) {
        //  A two-octet number denoting the time in days that this key is
        //  valid.  If this number is zero, then it does not expire.
        [packetBody getBytes:&_V3validityPeriod range:(NSRange){position, 2}];
        _V3validityPeriod = CFSwapInt16BigToHost(_V3validityPeriod);
        position = position + 2;
    }

    // A one-octet number denoting the public-key algorithm of this key.
    [packetBody getBytes:&_publicKeyAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // A series of multiprecision integers comprising the key material.
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // Algorithm-Specific Fields for RSA public keys:
            // MPI of RSA public modulus n;
            let mpiN = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_N atPosition:position];
            position = position + mpiN.packetLength;

            // MPI of RSA public encryption exponent e.
            let mpiE = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_E atPosition:position];
            position = position + mpiE.packetLength;

            self.publicMPIs = @[mpiN, mpiE];
        } break;
        case PGPPublicKeyAlgorithmDSA: {
            // - MPI of DSA prime p;
            let mpiP = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_P atPosition:position];
            position = position + mpiP.packetLength;

            // - MPI of DSA group order q (q is a prime divisor of p-1);
            let mpiQ = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_Q atPosition:position];
            position = position + mpiQ.packetLength;

            // - MPI of DSA group generator g;
            let mpiG = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_G atPosition:position];
            position = position + mpiG.packetLength;

            // - MPI of DSA public-key value y (= g**x mod p where x is secret).
            let mpiY = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_Y atPosition:position];
            position = position + mpiY.packetLength;

            self.publicMPIs = @[mpiP, mpiQ, mpiG, mpiY];
        } break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign: {
            // - MPI of Elgamal prime p;
            let mpiP = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_P atPosition:position];
            position = position + mpiP.packetLength;

            // - MPI of Elgamal group generator g;
            let mpiG = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_G atPosition:position];
            position = position + mpiG.packetLength;

            // - MPI of Elgamal public key value y (= g**x mod p where x is secret).
            let mpiY = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_Y atPosition:position];
            position = position + mpiY.packetLength;

            self.publicMPIs = @[mpiP, mpiG, mpiY];
        } break;
        case PGPPublicKeyAlgorithmECDSA: {
            // a variable-length field containing a curve OID
            UInt8 oidSize = 0;
            [packetBody getBytes:&oidSize range:(NSRange){position, 1}];
            position = position + 1;

            let curveIdentifierData = [packetBody subdataWithRange:(NSRange){position, oidSize}];
            self.curveOID = [[PGPCurveOID alloc] initWithIdentifierData: curveIdentifierData];
            position = position + oidSize;

            // MPI of an EC point representing a public key
            let mpiEC = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_EC atPosition:position];
            position = position + mpiEC.packetLength;
        } break;
        case PGPPublicKeyAlgorithmEdDSA: {
            // a variable-length field containing a curve OID
            UInt8 oidSize = 0;
            [packetBody getBytes:&oidSize range:(NSRange){position, 1}];
            position = position + 1;

            let curveIdentifierData = [packetBody subdataWithRange:(NSRange){position, oidSize}];
            self.curveOID = [[PGPCurveOID alloc] initWithIdentifierData: curveIdentifierData];
            position = position + oidSize;

            // MPI of an EC point representing a public key Q
            let mpiEC = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_EC atPosition:position];
            position = position + mpiEC.packetLength;
        } break;
        case PGPPublicKeyAlgorithmECDH: {
            // a variable-length field containing a curve OID
            UInt8 oidSize = 0;
            [packetBody getBytes:&oidSize range:(NSRange){position, 1}];
            position = position + 1;

            let curveIdentifierData = [packetBody subdataWithRange:(NSRange){position, oidSize}];
            self.curveOID = [[PGPCurveOID alloc] initWithIdentifierData: curveIdentifierData];
            position = position + oidSize;

            // a MPI of an EC point representing a public key;
            let mpiEC = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPI_EC atPosition:position];
            position = position + mpiEC.packetLength;

            // KDF parameters

            // a variable-length field containing KDF parameters
            UInt8 kdfSize = 0;
            [packetBody getBytes:&kdfSize range:(NSRange){position, 1}];
            position = position + 1;

            // a one-octet value 01, reserved for future extensions
            position = position + 1;

            // a one-octet hash function ID used with a KDF
            PGPHashAlgorithm kdfHashAlgorithm = PGPHashUnknown;
            [packetBody getBytes:&kdfHashAlgorithm range:(NSRange){position, 1}];
            position = position + 1;

            // a one-octet algorithm ID for the symmetric algorithm used to wrap the symmetric key used for the message encryption;
            PGPSymmetricAlgorithm kdfSymmetricAlgorithm = PGPSymmetricPlaintext;
            [packetBody getBytes:&kdfSymmetricAlgorithm range:(NSRange){position, 1}];
            position = position + 1;

            self.edchParameters = [[PGPCurveECDHParameters alloc] initWithHashAlgorithm:kdfHashAlgorithm symmetricAlgorithm:kdfSymmetricAlgorithm];
        } break;
        case PGPPublicKeyAlgorithmDiffieHellman:
        case PGPPublicKeyAlgorithmPrivate1:
        case PGPPublicKeyAlgorithmPrivate2:
        case PGPPublicKeyAlgorithmPrivate3:
        case PGPPublicKeyAlgorithmPrivate4:
        case PGPPublicKeyAlgorithmPrivate5:
        case PGPPublicKeyAlgorithmPrivate6:
        case PGPPublicKeyAlgorithmPrivate7:
        case PGPPublicKeyAlgorithmPrivate8:
        case PGPPublicKeyAlgorithmPrivate9:
        case PGPPublicKeyAlgorithmPrivate10:
        case PGPPublicKeyAlgorithmPrivate11:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Public key algorithm is not supported" }];
            }
        break;
    }

    return position;
}

/**
 *  Build new style public key data
 *
 *  @return public key data starting with version octet
 */
- (NSData *)buildKeyBodyData:(BOOL)forceV4 {
    let data = [NSMutableData dataWithCapacity:128];
    [data appendBytes:&_version length:1];

    UInt32 timestamp = (UInt32)[self.createDate timeIntervalSince1970];
    UInt32 timestampBE = CFSwapInt32HostToBig(timestamp);
    [data appendBytes:&timestampBE length:4];

    if (!forceV4 && self.version == 0x03) {
        // implementation MUST NOT generate a V3 key, but MAY accept it.
        // however it have to be generated here to calculate the very same fingerprint
        UInt16 V3ValidityPeriodBE = CFSwapInt16HostToBig(_V3validityPeriod);
        [data appendBytes:&V3ValidityPeriodBE length:2];
    }

    [data appendBytes:&_publicKeyAlgorithm length:1];

    // Curve OID
    if (self.publicKeyAlgorithm == PGPPublicKeyAlgorithmECDSA ||
        self.publicKeyAlgorithm == PGPPublicKeyAlgorithmEdDSA ||
        self.publicKeyAlgorithm == PGPPublicKeyAlgorithmECDH)
    {
        [data pgp_appendData:[self.curveOID export:nil]];
    }

    // publicMPI is always available, no need to decrypt
    for (PGPMPI *mpi in self.publicMPIs) {
        let exportMPI = [mpi exportMPI];
        [data pgp_appendData:exportMPI];
    }

    // KDF
    if (self.publicKeyAlgorithm == PGPPublicKeyAlgorithmECDH) {
        [data pgp_appendData:[self.edchParameters export:nil]];
    }

    return data;
}

// Old-style packet header for a key packet with two-octet length.
// Old but used by fingerprint and with signing
- (NSData *)exportKeyPacketOldStyle {
    let data = [NSMutableData data];

    let keyData = [self buildKeyBodyData:NO];

    NSUInteger length = keyData.length;
    UInt8 upper = (UInt8)(length >> 8);
    UInt8 lower = length & 0xff;
    UInt8 headWithLength[3] = {0x99, upper, lower};
    [data appendBytes:&headWithLength length:3];
    [data appendData:keyData];
    return data;
}

#pragma mark - PGPExportable

/**
 *  Packet data. Header with body data.
 *
 *  @param error error
 *
 *  @return data
 */
- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return [self buildKeyBodyData:NO];
    }];
}

#pragma mark - Encrypt & Decrypt

// data is mEMEEncoded
- (nullable NSArray<PGPMPI *> *)encryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm {
    switch (publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // return encrypted m
            let encryptedMData = [PGPRSA publicEncrypt:data withPublicKeyPacket:self];
            let m = [[PGPMPI alloc] initWithData:encryptedMData identifier:PGPMPI_M];
            return @[m];
        } break;
        case PGPPublicKeyAlgorithmElgamal: {
            let bigNums = [PGPElgamal publicEncrypt:data withPublicKeyPacket:self];
            let g_k = [[PGPMPI alloc] initWithBigNum:bigNums[0] identifier:PGPMPI_G];
            let m = [[PGPMPI alloc] initWithBigNum:bigNums[1] identifier:PGPMPI_M];
            return @[g_k, m];
        } break;
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmECDSA:
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        case PGPPublicKeyAlgorithmDiffieHellman:
        case PGPPublicKeyAlgorithmPrivate1:
        case PGPPublicKeyAlgorithmPrivate2:
        case PGPPublicKeyAlgorithmPrivate3:
        case PGPPublicKeyAlgorithmPrivate4:
        case PGPPublicKeyAlgorithmPrivate5:
        case PGPPublicKeyAlgorithmPrivate6:
        case PGPPublicKeyAlgorithmPrivate7:
        case PGPPublicKeyAlgorithmPrivate8:
        case PGPPublicKeyAlgorithmPrivate9:
        case PGPPublicKeyAlgorithmPrivate10:
        case PGPPublicKeyAlgorithmPrivate11:
            PGPLogWarning(@"Algorithm %@ is not supported.", @(publicKeyAlgorithm));
        break;
    }
    return nil;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToKeyPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToKeyPacket:(PGPPublicKeyPacket *)packet {
    return self.version == packet.version &&
           self.publicKeyAlgorithm == packet.publicKeyAlgorithm &&
           self.V3validityPeriod == packet.V3validityPeriod &&
           PGPEqualObjects(self.createDate, packet.createDate) &&
           PGPEqualObjects(self.publicMPIs, packet.publicMPIs);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.version;
    result = prime * result + self.publicKeyAlgorithm;
    result = prime * result + self.V3validityPeriod;
    result = prime * result + self.createDate.hash;
    result = prime * result + self.publicMPIs.hash;
    return result;
}


#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable duplicate = PGPCast([super copyWithZone:zone], PGPPublicKeyPacket);
    if (!duplicate) {
        return nil;
    }
    duplicate.version = self.version;
    duplicate.publicKeyAlgorithm = self.publicKeyAlgorithm;
    duplicate.V3validityPeriod = self.V3validityPeriod;
    duplicate.createDate = self.createDate;
    duplicate.publicMPIs = [[NSArray alloc] initWithArray:self.publicMPIs copyItems:YES];
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
