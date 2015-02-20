//
//  PGPKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//  see 11.1.Transferable Public Keys, 11.2.Transferable Secret Keys
//

#import "PGPKey.h"
#import "PGPFunctions.h"
#import "PGPPublicKeyPacket.h"
#import "PGPMPI.h"

@implementation PGPKey

- (instancetype)initWithPacket:(PGPPublicKeyPacket *)packet
{
    if (self = [super init]) {
        NSAssert([packet isKindOfClass:[PGPPublicKeyPacket class]], @"Invalid class");
        _packet = packet;
    }
    return self;
}

- (NSData *)fingerprint
{
    switch (self.packet.version) {
        case 0x04:
        {
            // A V4 fingerprint is the 160-bit SHA-1 hash
            NSError *error = nil;
            NSData *keyBody = [self.packet buildData:&error];
            if (!keyBody || error) {
                NSAssert(false, @"Missing key body");
                return nil;
            }
            NSData *keyData = [self.packet buildData:&error];
            NSData *lengthData = buildOldFormatLengthBytesForData(keyData);
            NSMutableData *toHash = [NSMutableData dataWithCapacity:keyData.length + lengthData.length];
            if (self.packet.version == 0x04) {
                [toHash appendData:lengthData];
            }
            [toHash appendData:keyData];
            
            return pgpCalculateSHA1(toHash.bytes, (unsigned int)toHash.length);
        }
            break;
        case 0x03:
        {
            // TODO: untested
            // The fingerprint of a V3 key is formed by hashing the body of the MPIs that form the key material
            NSError *error = nil;
            NSMutableData *toHash = [NSMutableData data];
            for (PGPMPI *mpi in self.packet.MPIs) {
                [toHash appendData:[mpi buildData:&error]];
            }

            // Finally, the Key ID and fingerprint of a subkey are calculated in the
            // same way as for a primary key, including the 0x99 as the first octet
            //    (even though this is not a valid packet ID for a public subkey).
            return pgpCalculateMD5(toHash.bytes, (unsigned int)toHash.length);
        }
            break;
        default:
            NSAssert(false, @"Shouldn't happend");
            break;
    }
    return nil;
}

/**
 *  Note that if V3 and V4 format keys share the same RSA key
 *  material, they will have different Key IDs as well as different
 *  fingerprints.
 *
 *  @return key id
 */
- (PGPKeyID *)keyID
{
    switch (self.packet.version) {
        case 0x04:
        {
            // For a V4 The Key ID is the low-order 64 bits of the fingerprint.
            NSData *fingerprint = [self fingerprint];
            NSAssert(fingerprint.length == 160 / 8, @"Invalid fingerprint");
            NSData *keyIDBytes = [fingerprint subdataWithRange:(NSRange){fingerprint.length - 8,8}];
            return [[PGPKeyID alloc] initWithBytes:keyIDBytes.bytes length:keyIDBytes.length];
        }
            break;
        case 0x03:
        {
            //TODO: untested
            // For a V3 key, the eight-octet Key ID consists of the low 64 bits of the public modulus of the RSA key.
            NSData *modulus = [self.packet mpiForIdentifier:@"N"];
            NSData *keyIDBytes = [modulus subdataWithRange:(NSRange){modulus.length - 8,8}];
            return [[PGPKeyID alloc] initWithBytes:keyIDBytes.bytes length:keyIDBytes.length];
        }
            break;
        default:
            break;
    }
    return nil;
}

@end
