//
//  PGPSecretKeyPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  A Secret-Key packet contains all the information that is found in a
//  Public-Key packet, including the public-key material, but also
//  includes the secret-key material after all the public-key fields.

#import "PGPSecretKeyPacket.h"
#import "PGPString2Key.h"
#import "PGPMPI.h"

#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/camellia.h>
#include <openssl/blowfish.h>

@interface PGPSecretKeyPacket ()

@property (assign) BOOL isEncrypted;
@property (assign) PGPS2KUsage s2kUsage;
@property (strong) PGPString2Key *s2k;
@property (assign) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (strong) NSData *ivData;
@property (strong) NSData *encryptedMPIData;
@property (strong) NSArray *mpi;

@end

@implementation PGPSecretKeyPacket

- (id)init
{
    if (self = [super init]) {
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPSecretKeyPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody
{
    NSUInteger position = [super parsePacketBody:packetBody];
    //  5.5.3.  Secret-Key Packet Formats

    // One octet indicating string-to-key usage conventions
    [packetBody getBytes:&_s2kUsage range:(NSRange){position, 1}];
    position = position + 1;

    if (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
        // moved to readEncrypted:astartingAtPosition
    } else if (self.s2kUsage != PGPS2KUsageNone) {
        // this is version 3, looks just like a V4 simple hash
        self.symmetricAlgorithm = (PGPSymmetricAlgorithm)self.s2kUsage; // this is tricky, but this is right. V3 algorithm is in place of s2kUsage of V4
        self.s2kUsage = PGPS2KUsageEncrypted;
        
        self.s2k = [[PGPString2Key alloc] init]; // not really parsed s2k
        self.s2k.specifier = PGPS2KSpecifierSimple;
        self.s2k.algorithm = PGPHashMD5;
    }

    self.isEncrypted = (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed);

    if (self.isEncrypted) {
        position = [self readEncrypted:packetBody startingAtPosition:position];
    } else {
        position = [self readPlaintext:packetBody startingAtPosition:position];
    }

    return position;
}

/**
 *  Encrypted algorithm-specific fields for secret keys
 *
 *  @param packetBody packet data
 *  @param position   position offset
 *
 *  @return new position offset
 */
- (NSUInteger) readEncrypted:(NSData *)packetBody startingAtPosition:(NSUInteger)position
{
    // If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm
    [packetBody getBytes:&_symmetricAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // S2K
    self.s2k = [PGPString2Key string2KeyFromData:packetBody atPosition:position];
    position = position + self.s2k.length;

    // Initial Vector (IV) of the same length as the cipher's block size
    NSUInteger blockSize = [self blockSizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
    NSAssert(blockSize <= 16, @"invalid blockSize");

    self.ivData = [packetBody subdataWithRange:(NSRange) {position, blockSize}];
    position = position + blockSize;

#ifdef DEBUG
    UInt8 *IV = (UInt8 *)self.ivData.bytes;
    NSLog(@"IV %#02X %#02X %#02X %#02X %#02X %#02X %#02X %#02X", IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);
#endif

    NSData *hashOrChecksum = nil;
    switch (self.s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed:
        {
            // encrypted MPIs
            self.encryptedMPIData = [packetBody subdataWithRange:(NSRange) {position, self.bodyLength - position - 20}];
            position = position + self.encryptedMPIData.length;

            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            hashOrChecksum = [packetBody subdataWithRange:(NSRange){position,20}];
            position = position + 20;
        }
            break;
        default:
        {
            // encrypted MPIs
            self.encryptedMPIData = [packetBody subdataWithRange:(NSRange) {position, self.bodyLength - position - 2}];
            position = position + self.encryptedMPIData.length;

            // a two-octet checksum of the plaintext of the algorithm-specific portion
            hashOrChecksum = [packetBody subdataWithRange:(NSRange){position,2}];
            position = position + 2;
        }
            break;
    }
    return position;
}

/**
 *  Plaintext algorithm-specific fields for secret keys
 *
 *  @param packetBody packet data
 *  @param position   position offset
 *
 *  @return new position offset
 */
- (NSUInteger) readPlaintext:(NSData *)packetBody startingAtPosition:(NSUInteger)position
{
    switch (self.algorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA secret exponent d.
            PGPMPI *mpiD = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiD.identifier = @"D";
            position = position + mpiD.length;

            // MPI of RSA secret prime value p.
            PGPMPI *mpiP = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiP.identifier = @"P";
            position = position + mpiP.length;

            // MPI of RSA secret prime value q (p < q).
            PGPMPI *mpiQ = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiQ.identifier = @"Q";
            position = position + mpiQ.length;

            // MPI of u, the multiplicative inverse of p, mod q.
            PGPMPI *mpiU = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiU.identifier = @"U";
            position = position + mpiU.length;

            self.mpi = [NSArray arrayWithObjects:mpiD, mpiP, mpiQ, mpiU, nil];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        {
            // MPI of DSA secret exponent x.
            PGPMPI *mpiX = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiX.identifier = @"X";
            position = position + mpiX.length;

            self.mpi = [NSArray arrayWithObjects:mpiX, nil];
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        {
            // MPI of Elgamal secret exponent x.
            PGPMPI *mpiX = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiX.identifier = @"X";
            position = position + mpiX.length;

            self.mpi = [NSArray arrayWithObjects:mpiX, nil];
        }
            break;
        default:
            break;
    }


    NSData *hashOrChecksum = nil;
    switch (self.s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed:
        {
            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            hashOrChecksum = [packetBody subdataWithRange:(NSRange){position,20}];
            position = position + 20;
        }
            break;
        default:
        {
            // a two-octet checksum of the plaintext of the algorithm-specific portion
            hashOrChecksum = [packetBody subdataWithRange:(NSRange){position,2}];
            position = position + 2;
        }
            break;
    }

    return position;
}

/**
 *  Decrypt parsed encrypted packet
 */
- (void) decrypt
{
    if (!self.isEncrypted) {
        return;
    }

    // Keysize
    //NSUInteger keySize = [self keySizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
    //NSAssert(keySize <= 32, @"invalid keySize");

    // Hash size
    //NSUInteger hashSize = [self hashSizeOfHashAlhorithm:self.s2k.algorithm];
    //NSAssert(hashSize <= 64, @"invalid hashSize");


    //TODO: decrypt
    // 3.7.2.1.  Secret-Key Encryption
    // 3.7.2.2.  Symmetric-Key Message Encryption
    // CFB etc...
    // With V4 keys, a simpler method is used.  All secret MPI values are
    // encrypted in CFB mode, including the MPI bitcount prefix.
    // crypto.cfb.normalDecrypt(symmetric, key, ciphertext, iv);

}

#pragma mark - Private

- (NSUInteger) blockSizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
{
    switch (symmetricAlgorithm) {
        case PGPSymmetricIDEA:
            return IDEA_BLOCK;
        case PGPSymmetricTripleDES:
            return 8;
        case PGPSymmetricCAST5:
            return CAST_BLOCK;
        case PGPSymmetricBlowfish:
            return 16; // 64bit
        case PGPSymmetricAES128:
        case PGPSymmetricAES192:
        case PGPSymmetricAES256:
            return 16;
        case PGPSymmetricTwofish256:
            return 16; // 128bit
        default:
            break;
    }
    return NSNotFound;
}

- (NSUInteger) keySizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
{
    switch (symmetricAlgorithm) {
        case PGPSymmetricIDEA:
            return IDEA_KEY_LENGTH;
        case PGPSymmetricTripleDES:
            return 8;
        case PGPSymmetricCAST5:
            return CAST_KEY_LENGTH;
        case PGPSymmetricBlowfish:
            return 16; // 16 bit
        case PGPSymmetricAES128:
            return 16; // 128 bit
        case PGPSymmetricAES192:
            return 23; // 192 bit
        case PGPSymmetricAES256:
            return 32; // 256 bit
        case PGPSymmetricTwofish256:
            return 16; // 128bit (??or 32)
        default:
            break;
    }
    return NSNotFound;
}

- (NSUInteger) hashSizeOfHashAlhorithm:(PGPHashAlgorithm)hashAlgorithm
{
    switch (hashAlgorithm) {
        case PGPHashMD5:
            return 16;
        case PGPHashSHA1:
            return 20;
        case PGPHashSHA224:
            return 28;
        case PGPHashSHA256:
            return 32;
        case PGPHashSHA384:
            return 48;
        case PGPHashSHA512:
            return 64;
        case PGPHashRIPEMD160:
            return 20; // TODO: confirm RIPE/MD 160 value
        default:
            break;
    }
    return NSNotFound;
}


@end
