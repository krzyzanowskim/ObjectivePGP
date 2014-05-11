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

@implementation PGPSecretKeyPacket

- (PGPPacketTag)tag
{
    return PGPSecretKeyPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody
{
    NSUInteger position = [super parsePacketBody:packetBody];
    //  5.5.3.  Secret-Key Packet Formats

    PGPSymmetricAlgorithm symmetricAlgorithm = 0;
    PGPString2Key *s2k                       = nil;
    BOOL isEncrypted                         = NO;

    // One octet indicating string-to-key usage conventions
    PGPS2KUsage s2kUsage = 0;
    [packetBody getBytes:&s2kUsage range:(NSRange){position, 1}];
    position = position + 1;

    if (s2kUsage == PGPS2KUsageEncrypted || s2kUsage == PGPS2KUsageEncryptedAndHashed) {

        [packetBody getBytes:&symmetricAlgorithm range:(NSRange){position, 1}];
        position = position + 1;

        // S2K
        s2k = [PGPString2Key string2KeyFromData:packetBody atPosition:position];
        position = position + s2k.length;
    } else if (s2kUsage != PGPS2KUsageNone) {
        // this is version 3, looks just like a V4 simple hash
        // this is tricky, but this is right. V3 algorithm is in place of s2kUsage of V4
        symmetricAlgorithm = (PGPSymmetricAlgorithm)s2kUsage;
        s2kUsage = PGPS2KUsageEncrypted;
        s2k.specifier = PGPS2KSpecifierSimple;
        s2k.algorithm = PGPHashMD5;
    }

    isEncrypted = (s2kUsage == PGPS2KUsageEncrypted || s2kUsage == PGPS2KUsageEncryptedAndHashed);

    if (isEncrypted) {
        // Initial Vector (IV) of the same length as the cipher's block size
        NSUInteger blockSize = [self blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];
        NSAssert(blockSize <= 16, @"invalid blockSize");

        UInt8 *IV = (UInt8 *)[packetBody subdataWithRange:(NSRange) {position, blockSize}].bytes;
        position = position + blockSize;

#ifdef DEBUG
        NSLog(@"IV %#02X %#02X %#02X %#02X %#02X %#02X %#02X %#02X", IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);
#endif

        // Keysize
        NSUInteger keySize = [self keySizeOfSymmetricAlhorithm:symmetricAlgorithm];
        NSAssert(keySize <= 32, @"invalid keySize");

        // Hash size
        NSUInteger hashSize = [self hashSizeOfHashAlhorithm:s2k.algorithm];
        NSAssert(hashSize <= 64, @"invalid hashSize");

        //TODO: Encrypted secure key - with passphase.
        // 3.7.2.1.  Secret-Key Encryption
        // 3.7.2.2.  Symmetric-Key Message Encryption
        // CFB etc...
        // With V4 keys, a simpler method is used.  All secret MPI values are
        // encrypted in CFB mode, including the MPI bitcount prefix.
        // crypto.cfb.normalDecrypt(symmetric, key, ciphertext, iv);
    } else {
        // Plaintext
        // Algorithm-Specific Fields for RSA secret keys:
        switch (self.algorithm) {
            case PGPPublicKeyAlgorithmRSA:
            case PGPPublicKeyAlgorithmRSAEncryptOnly:
            case PGPPublicKeyAlgorithmRSASignOnly:
            {
                // multiprecision integer (MPI) of RSA secret exponent d.
                PGPMPI *mpiD = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
                position = position + mpiD.length;

                // MPI of RSA secret prime value p.
                PGPMPI *mpiP = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
                position = position + mpiP.length;

                // MPI of RSA secret prime value q (p < q).
                PGPMPI *mpiQ = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
                position = position + mpiQ.length;

                // MPI of u, the multiplicative inverse of p, mod q.
                PGPMPI *mpiU = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
                position = position + mpiU.length;
            }
                break;
            case PGPPublicKeyAlgorithmDSA:
            {
                // MPI of DSA secret exponent x.
                PGPMPI *mpiX = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
                position = position + mpiX.length;
            }
                break;
            case PGPPublicKeyAlgorithmElgamal:
            case PGPPublicKeyAlgorithmElgamalEncryptorSign:
            {
                // MPI of Elgamal secret exponent x.
                PGPMPI *mpiX = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
                position = position + mpiX.length;
            }
                break;
            default:
                break;
        }
    }

    NSData *checksumData = nil;
    switch (s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed:
            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            checksumData = [packetBody subdataWithRange:(NSRange){position,20}];
            position = position + 20;
            break;
        default:
            // a two-octet checksum of the plaintext of the algorithm-specific portion
            checksumData = [packetBody subdataWithRange:(NSRange){position,2}];
            position = position + 2;
            break;
    }

    // move to the end
    // position = self.bodyLength;
    return position;
}

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
