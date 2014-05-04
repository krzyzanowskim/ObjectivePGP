//
//  OpenPGPPublicKey.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKey.h"
#import "PGPTypes.h"
#import "PGPMPI.h"

@interface PGPPublicKey ()
@property (assign) UInt16 V3validityPeriod;
@end

@implementation PGPPublicKey

- (instancetype) initWithBody:(NSData *)packetData
{
    if (self = [self init]) {
        [self parsePacketBody:packetData];
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPPublicKeyPacketTag;
}

/**
 *  5.5.2.  Public-Key Packet Formats
 *
 *  @param packetBody Packet body
 */
- (void) parsePacketBody:(NSData *)packetBody
{
    //TODO: V3 keys are deprecated; an implementation MUST NOT generate a V3 key, but MAY accept it.

    NSUInteger position = 0;
    //UInt8 *bytes = (UInt8 *)packetBody.bytes;
    // A one-octet version number (2,3,4).
    UInt8 version;
    [packetBody getBytes:&version range:(NSRange){position,1}];
    _version = version;
    position = position + 1;

    // A four-octet number denoting the time that the key was created.
    UInt32 timestamp = 0;
    [packetBody getBytes:&timestamp range:(NSRange){position,4}];
    _timestamp = CFSwapInt32BigToHost(timestamp);
    position = position + 4;

    if (_version == 0x03) {
        //  A two-octet number denoting the time in days that this key is
        //  valid.  If this number is zero, then it does not expire.
        UInt16 validityPeriod;
        [packetBody getBytes:&validityPeriod range:(NSRange){position,2}];
        _V3validityPeriod = validityPeriod;
        position = position + 2;
    }

    // A one-octet number denoting the public-key algorithm of this key.
    UInt8 algorithm = 0;
    [packetBody getBytes:&algorithm range:(NSRange){position,1}];
    _algorithm = algorithm;
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
            //TODO: DSA
            // - MPI of DSA prime p;
            // - MPI of DSA group order q (q is a prime divisor of p-1);
            // - MPI of DSA group generator g;
            // - MPI of DSA public-key value y (= g**x mod p where x is secret).
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptOnly:
        {
            //TODO: Elgamal
            // - MPI of Elgamal prime p;
            // - MPI of Elgamal group generator g;
            // - MPI of Elgamal public key value y (= g**x mod p where x is secret).
        }
            break;
        default:
            @throw [NSException exceptionWithName:@"Unknown Algorithm" reason:@"Given algorithm is not supported" userInfo:nil];
            break;
    }
}

@end
