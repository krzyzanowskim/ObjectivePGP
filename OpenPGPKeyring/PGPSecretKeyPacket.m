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

#import "PGPCryptoUtils.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

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
@property (strong) NSData *encryptedMPIAndHashData;
@property (strong) NSData *hashOrChecksum;
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
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
    NSAssert(blockSize <= 16, @"invalid blockSize");

    self.ivData = [packetBody subdataWithRange:(NSRange) {position, blockSize}];
    position = position + blockSize;


    // encrypted MPIs
    // checksum or hash is encrypted together with the algorithm-specific fields (if string-to-key usage octet is not zero).
    self.encryptedMPIAndHashData = [packetBody subdataWithRange:(NSRange) {position, self.bodyLength - position}];
    position = position + self.encryptedMPIAndHashData.length;

#ifdef DEBUG
    //TODO: REMOVE, just for testing purpose
    [self decrypt:@"1234"];
#endif
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

    switch (self.s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed:
        {
            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:self.s2k.algorithm];
            NSAssert(hashSize <= 64, @"invalid hashSize");

            self.hashOrChecksum = [packetBody subdataWithRange:(NSRange){position, hashSize}];
            position = position + self.hashOrChecksum.length;
        }
            break;
        default:
        {
            // a two-octet checksum of the plaintext of the algorithm-specific portion
            self.hashOrChecksum = [packetBody subdataWithRange:(NSRange){position,2}];
            position = position + 2;
        }
            break;
    }

    return position;
}

/**
 *  Decrypt parsed encrypted packet
 */
- (void) decrypt:(NSString *)passphrase
{
    if (!self.isEncrypted) {
        return;
    }

    if (!self.ivData) {
        return;
    }

    // Keysize
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
    NSAssert(keySize <= 32, @"invalid keySize");

#ifdef DEBUG
    UInt8 *IV = (UInt8 *)self.ivData.bytes;
    NSLog(@"IV %#02X %#02X %#02X %#02X %#02X %#02X %#02X %#02X", IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);
#endif

    //FIXME: not here, just for testing (?)
    NSData *keyData = [self.s2k produceKeyWithPassphrase:passphrase keySize:keySize];

    const void *encryptedBytes = self.encryptedMPIAndHashData.bytes;
    // decrypt CAST5 with CFB
    switch (self.symmetricAlgorithm) {
        case PGPSymmetricCAST5:
        {
            if (self.s2k.specifier == PGPS2KSpecifierIteratedAndSalted) {

                // initialize
                CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
                CAST_set_key(encrypt_key, keySize, keyData.bytes);

                CAST_KEY *decrypt_key = calloc(1, sizeof(CAST_KEY));
                CAST_set_key(decrypt_key, keySize, keyData.bytes);

                // TODO: see __ops_decrypt_init block_encrypt siv,civ,iv comments. siv is needed for weird v3 resync,
                // wtf civ ???
                // CAST_ecb_encrypt(in, out, encrypt_key, CAST_ENCRYPT);

                CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
                if (ctx) {
                    CC_SHA1_Init(ctx);
                }

                //TODO: maybe CommonCrypto with kCCModeCFB in place of OpenSSL
                NSUInteger outButterLength = self.encryptedMPIAndHashData.length;
                UInt8 *outBuffer = calloc(outButterLength, sizeof(UInt8));
                int num = 0; //	how much of the 64bit block we have used
                CAST_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)self.ivData.bytes, &num, CAST_DECRYPT);
                NSLog(@"decrypted %@", @(num));
                NSData *decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];
                if (outBuffer) {
                    free(outBuffer);
                }

                // now read mpis
                [self readPlaintext:decryptedData startingAtPosition:0];
            }

        }
            break;

        default:
            break;
    }


    //TODO: decrypt
    // 3.7.2.1.  Secret-Key Encryption
    // 3.7.2.2.  Symmetric-Key Message Encryption
    // CFB etc...
    // With V4 keys, a simpler method is used.  All secret MPI values are
    // encrypted in CFB mode, including the MPI bitcount prefix.
    // crypto.cfb.normalDecrypt(symmetric, key, ciphertext, iv);
}



@end
