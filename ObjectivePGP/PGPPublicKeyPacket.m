//
//  OpenPGPPublicKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket.h"
#import "PGPTypes.h"
#import "PGPMPI.h"
#import "NSData+PGPUtils.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface PGPPublicKeyPacket ()
@property (strong, readwrite) NSArray *publicMPI;
@property (strong, nonatomic, readwrite) PGPFingerprint *fingerprint;
@property (strong, nonatomic, readwrite) PGPKeyID *keyID;
@property (assign, readwrite) UInt16 V3validityPeriod;
@end

@implementation PGPPublicKeyPacket

- (PGPPacketTag)tag
{
    return PGPPublicKeyPacketTag;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@", [super description], self.keyID];
}

/**
 *  12.2.  Key IDs and Fingerprints
 *
 *  @return keyID
 */
- (PGPKeyID *)keyID
{
    if (!_keyID) {
        _keyID = [[PGPKeyID alloc] initWithFingerprint:self.fingerprint];
    }

    return _keyID;
}

/**
 *  12.2.  Key IDs and Fingerprints
 *  Calculate fingerprint
 *
 *  @return Fingerprint data
 */
- (PGPFingerprint *)fingerprint
{
    if (!_fingerprint) {
        NSMutableData *toHashData = [NSMutableData data];

        NSData *publicKeyData = [self buildPublicKeyDataAndForceV4:NO];

        NSUInteger length = publicKeyData.length;
        UInt8 upper = length >> 8;
        UInt8 lower = length & 0xff;
        UInt8 headWithLength[3] = {0x99, upper, lower};
        [toHashData appendBytes:&headWithLength length:3];
        [toHashData appendData:publicKeyData];
        
        NSData *sha1Hash = [toHashData SHA1];
        _fingerprint = [[PGPFingerprint alloc] initWithData:sha1Hash];
    }
    return _fingerprint;
}

/**
 *  Build public key data for fingerprint
 *
 *  @return public key data starting with version octet
 */
- (NSData *) buildPublicKeyDataAndForceV4:(BOOL)forceV4
{
    NSMutableData *data = [NSMutableData dataWithCapacity:128];
    [data appendBytes:&_version length:1];

    UInt32 timestampBE = CFSwapInt32HostToBig(_timestamp);
    [data appendBytes:&timestampBE length:4];

    if (!forceV4 && _version == 0x03) {
        // implementation MUST NOT generate a V3 key, but MAY accept it.
        // however it have to be generated here to calculate the very same fingerprint
        UInt16 V3ValidityPeriodBE = CFSwapInt16HostToBig(_V3validityPeriod);
        [data appendBytes:&V3ValidityPeriodBE length:2];
    }

    [data appendBytes:&_algorithm length:1];

    // publicMPI is allways available, no need to decrypt
    for (PGPMPI *mpi in self.publicMPI) {
        [data appendData:[mpi buildData]];
    }
    return [data copy];
}

/**
 *  5.5.2.  Public-Key Packet Formats
 *
 *  @param packetBody Packet body
 */
- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    //TODO: V3 keys are deprecated; an implementation MUST NOT generate a V3 key, but MAY accept it.

    // A one-octet version number (2,3,4).
    [packetBody getBytes:&_version range:(NSRange){position,1}];
    position = position + 1;

    NSAssert(self.version >= 3, @"To old packet version");

    // A four-octet number denoting the time that the key was created.
    [packetBody getBytes:&_timestamp range:(NSRange){position,4}];
    _timestamp = CFSwapInt32BigToHost(_timestamp);
    position = position + 4;

    if (_version == 0x03) {
        //  A two-octet number denoting the time in days that this key is
        //  valid.  If this number is zero, then it does not expire.
        [packetBody getBytes:&_V3validityPeriod range:(NSRange){position,2}];
        _V3validityPeriod = CFSwapInt16BigToHost(_V3validityPeriod);
        position = position + 2;
    }

    // A one-octet number denoting the public-key algorithm of this key.
    [packetBody getBytes:&_algorithm range:(NSRange){position,1}];
    position = position + 1;

    // A series of multiprecision integers comprising the key material.
    switch (self.algorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // Algorithm-Specific Fields for RSA public keys:
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiN.identifier = @"N";
            position = position + mpiN.length;

            // MPI of RSA public encryption exponent e.
            PGPMPI *mpiE = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiE.identifier = @"E";
            position = position + mpiE.length;

            self.publicMPI = [NSArray arrayWithObjects:mpiN, mpiE, nil];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // - MPI of DSA prime p;
            PGPMPI *mpiP = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiP.identifier = @"P";
            position = position + mpiP.length;

            // - MPI of DSA group order q (q is a prime divisor of p-1);
            PGPMPI *mpiQ = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiQ.identifier = @"Q";
            position = position + mpiQ.length;

            // - MPI of DSA group generator g;
            PGPMPI *mpiG = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiG.identifier = @"G";
            position = position + mpiG.length;

            // - MPI of DSA public-key value y (= g**x mod p where x is secret).
            PGPMPI *mpiY = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiY.identifier = @"Y";
            position = position + mpiY.length;

            self.publicMPI = [NSArray arrayWithObjects:mpiP, mpiQ, mpiG, mpiY, nil];
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        {
            // - MPI of Elgamal prime p;
            PGPMPI *mpiP = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiP.identifier = @"P";
            position = position + mpiP.length;

            // - MPI of Elgamal group generator g;
            PGPMPI *mpiG = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiG.identifier = @"G";
            position = position + mpiG.length;

            // - MPI of Elgamal public key value y (= g**x mod p where x is secret).
            PGPMPI *mpiY = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiY.identifier = @"Y";
            position = position + mpiY.length;

            self.publicMPI = [NSArray arrayWithObjects:mpiP, mpiG, mpiY, nil];
        }
            break;
        default:
            @throw [NSException exceptionWithName:@"Unknown Algorithm" reason:@"Given algorithm is not supported" userInfo:nil];
            break;
    }

    return position;
}

@end
