//
//  OpenPGPPublicKey.m
//  OpenPGPKeyring
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
@property (assign) UInt16 V3validityPeriod;
@end

@implementation PGPPublicKeyPacket

- (PGPPacketTag)tag
{
    return PGPPublicKeyPacketTag;
}

- (PGPKeyID *)keyID
{
    NSData *fingerprintData = self.fingerprint;
    PGPKeyID *kid = [[PGPKeyID alloc] initWithLongKey:[fingerprintData subdataWithRange:(NSRange){fingerprintData.length - 8,8}]];
    return kid;
}

- (NSData *) fingerprint
{
    NSMutableData *toHashData = [NSMutableData data];

    //FIXME: wrong length for seckey, should take just public key length not whole key
    NSUInteger length = self.bodyData.length;
    UInt8 upper = length >> 8;
    UInt8 lower = length & 0xff;
    UInt8 headWithLength[3] = {0x99, upper, lower};
    [toHashData appendBytes:&headWithLength length:3];
    NSData *publicKeyData = [self buildPublicKeyData];
    [toHashData appendData:publicKeyData];
    
    NSData *sha1Hash = [toHashData SHA1];

    return sha1Hash;
}

- (NSData *) buildPublicKeyData
{
    NSMutableData *data = [NSMutableData dataWithCapacity:128];
    [data appendBytes:&_version length:1];

    UInt32 timestamp = CFSwapInt32HostToBig(_timestamp);
    [data appendBytes:&timestamp length:4];

    if (_version == 0x03) {
        //TODO: v3 support here
    }

    [data appendBytes:&_algorithm length:1];

    for (PGPMPI *mpi in self.mpi) {
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

    // A four-octet number denoting the time that the key was created.
    [packetBody getBytes:&_timestamp range:(NSRange){position,4}];
    _timestamp = CFSwapInt32BigToHost(_timestamp);
    position = position + 4;

    if (_version == 0x03) {
        //  A two-octet number denoting the time in days that this key is
        //  valid.  If this number is zero, then it does not expire.
        UInt16 validityPeriod = 0;
        [packetBody getBytes:&validityPeriod range:(NSRange){position,2}];
        _V3validityPeriod = CFSwapInt16BigToHost(validityPeriod);
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

            self.mpi = [NSArray arrayWithObjects:mpiN, mpiE, nil];
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

            self.mpi = [NSArray arrayWithObjects:mpiP, mpiQ, mpiG, mpiY, nil];
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

            self.mpi = [NSArray arrayWithObjects:mpiP, mpiG, mpiY, nil];
        }
            break;
        default:
            @throw [NSException exceptionWithName:@"Unknown Algorithm" reason:@"Given algorithm is not supported" userInfo:nil];
            break;
    }

    return position;
}

@end
