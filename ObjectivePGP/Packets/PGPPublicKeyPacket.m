//
//  PGPPublicKeyPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//  5.5.1.1.  Public-Key Packet (Tag 6)
//  A Public-Key packet starts a series of packets that forms an OpenPGP
//  key (sometimes called an OpenPGP certificate).


#import "PGPPublicKeyPacket.h"
#import "PGPCommon.h"
#import "NSInputStream+PGP.h"
#import "NSOutputStream+PGP.h"
#import "PGPMPI.h"
#import "NSMutableData+PGP.h"

@implementation PGPPublicKeyPacket

+ (instancetype) readFromStream:(NSInputStream *)inputStream maxLength:(NSUInteger)maxLength error:(NSError * __autoreleasing *)error
{
    PGPPublicKeyPacket *packet = [[PGPPublicKeyPacket alloc] init];
    
    // A one-octet version number
    UInt8 version = [inputStream readUInt8];
    packet.version = version;
    NSAssert(version >= 0x03 && version <= 0x04, @"Version not supported");
    if (version < 0x03 && version > 0x04) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Version %@ not supported", @(version)]}];
        }
        return nil;
    }
    
    // A four-octet number denoting the time that the key was created.
    UInt32 timestamp = [inputStream readUInt32BE];
    if (timestamp) {
        packet.createDate = [NSDate dateWithTimeIntervalSince1970:timestamp];
    }
    
    if (version == 0x03) {
        // A two-octet number denoting the time in days that this key is
        // valid.  If this number is zero, then it does not expire.
        UInt16 validityPeriod = [inputStream readUInt16BE];
        packet.validityPeriod = validityPeriod;
    }
    
    // A one-octet number denoting the public-key algorithm of this key.
    packet.keyAlgorithm = [inputStream readUInt8];
    
    // A series of multiprecision integers comprising the key material.
    NSMutableOrderedSet *mpis = [NSMutableOrderedSet orderedSet];
    switch (packet.keyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [PGPMPI readFromStream:inputStream error:error];
            mpiN.identifier = @"N";
            [mpis addObject:mpiN];
            // MPI of RSA public encryption exponent e.
            PGPMPI *mpiE = [PGPMPI readFromStream:inputStream error:error];
            mpiE.identifier = @"E";
            [mpis addObject:mpiE];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA prime p;
            PGPMPI *mpiP = [PGPMPI readFromStream:inputStream error:error];
            mpiP.identifier = @"P";
            [mpis addObject:mpiP];
            
            //MPI of DSA group order q (q is a prime divisor of p-1);
            PGPMPI *mpiQ = [PGPMPI readFromStream:inputStream error:error];
            mpiQ.identifier = @"Q";
            [mpis addObject:mpiQ];
            
            //MPI of DSA group generator g;
            PGPMPI *mpiG = [PGPMPI readFromStream:inputStream error:error];
            mpiG.identifier = @"G";
            [mpis addObject:mpiG];
            
            //MPI of DSA public-key value y (= g**x mod p where x is secret).
            PGPMPI *mpiY = [PGPMPI readFromStream:inputStream error:error];
            mpiY.identifier = @"Y";
            [mpis addObject:mpiY];
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
            {
                //MPI of Elgamal prime p;
                PGPMPI *mpiP = [PGPMPI readFromStream:inputStream error:error];
                mpiP.identifier = @"P";
                [mpis addObject:mpiP];
                
                //MPI of Elgamal group generator g;
                PGPMPI *mpiG = [PGPMPI readFromStream:inputStream error:error];
                mpiG.identifier = @"G";
                [mpis addObject:mpiG];
                
                //MPI of Elgamal public key value y (= g**x mod p where x is secret).
                PGPMPI *mpiY = [PGPMPI readFromStream:inputStream error:error];
                mpiY.identifier = @"Y";
                [mpis addObject:mpiY];
            }
            break;
        default:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Public key algorithm %@ is not supported", @(packet.keyAlgorithm)]}];
            }
            return nil;
    }

    packet.MPIs = [mpis copy];
    return packet;
}

- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(outputStream);
    NSData *packetData = [self buildData:error];
    if (!packetData || *error) {
        return NO;
    }
    return [outputStream writeData:packetData];
}

- (NSData *) buildData:(NSError * __autoreleasing *)error
{
    NSMutableData *outputData = [NSMutableData data];
    
    [outputData appendUInt8:self.version];
    [outputData appendUInt32BE:[self.createDate timeIntervalSince1970]];
    if (self.version == 0x03) {
        [outputData appendUInt16BE:self.validityPeriod];
    }
    [outputData appendUInt8:self.keyAlgorithm];
    
    for (PGPMPI *mpi in self.MPIs) {
        [outputData appendData:[mpi buildData:error]];
    }
    
    return [outputData copy];
}

- (NSData *) mpiForIdentifier:(NSString *)key
{
    NSParameterAssert(key);
    return [[self.MPIs filteredOrderedSetUsingPredicate:[NSPredicate predicateWithFormat:@"SELF.identifier == %@", key]] firstObject];
}

@end
