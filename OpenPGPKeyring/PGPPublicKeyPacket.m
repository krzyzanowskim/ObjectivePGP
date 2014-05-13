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

@interface PGPPublicKeyPacket ()
@property (assign) UInt16 V3validityPeriod;
@end

@implementation PGPPublicKeyPacket

- (PGPPacketTag)tag
{
    return PGPPublicKeyPacketTag;
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
            position = position + mpiN.length;

            // MPI of RSA public encryption exponent e.
            PGPMPI *mpiE = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiE.length;
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // - MPI of DSA prime p;
            PGPMPI *mpiP = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiP.length;

            // - MPI of DSA group order q (q is a prime divisor of p-1);
            PGPMPI *mpiQ = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiQ.length;

            // - MPI of DSA group generator g;
            PGPMPI *mpiG = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiG.length;

            // - MPI of DSA public-key value y (= g**x mod p where x is secret).
            PGPMPI *mpiY = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiY.length;
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        {
            // - MPI of Elgamal prime p;
            PGPMPI *mpiP = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiP.length;

            // - MPI of Elgamal group generator g;
            PGPMPI *mpiG = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiG.length;

            // - MPI of Elgamal public key value y (= g**x mod p where x is secret).
            PGPMPI *mpiY = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiY.length;
        }
            break;
        default:
            @throw [NSException exceptionWithName:@"Unknown Algorithm" reason:@"Given algorithm is not supported" userInfo:nil];
            break;
    }
    return position;
}

@end
