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

- (void) parsePacketBody:(NSData *)packetBody
{
    //UInt8 *bytes = (UInt8 *)packetBody.bytes;
    // A one-octet version number (4).
    UInt8 version;
    [packetBody getBytes:&version range:(NSRange){0,1}];
    _version = version;

    // A four-octet number denoting the time that the key was created.
    UInt32 timestamp = 0;
    [packetBody getBytes:&timestamp range:(NSRange){1,4}];
    _timestamp = CFSwapInt32BigToHost(timestamp);

    // A one-octet number denoting the public-key algorithm of this key.
    UInt8 algorithm = 0;
    [packetBody getBytes:&algorithm range:(NSRange){5,1}];
    _algorithm = algorithm;

    // A series of multiprecision integers comprising the key material.
    switch (self.algorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // Algorithm-Specific Fields for RSA public keys:
            NSUInteger position = 6;

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
