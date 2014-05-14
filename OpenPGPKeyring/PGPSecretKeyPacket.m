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
#import "NSData+PGPUtils.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/camellia.h>
#include <openssl/blowfish.h>

@interface PGPSecretKeyPacket ()
@property (strong) NSData *encryptedMPIAndHashData;
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

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    //  5.5.3.  Secret-Key Packet Formats

    NSAssert(self.version == 0x04,@"Only Secret Key version 4 is supported. Found version %@", @(self.version));

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

    NSData *encryptedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
    if (self.isEncrypted) {
        position = position + [self parseEncryptedPart:encryptedData error:error];
    } else {
        position = position + [self parseCleartextPart:encryptedData error:error];
    }

    return position;
}

/**
 *  Encrypted algorithm-specific fields for secret keys
 *
 *  @param packetBody packet data
 *  @param position   position offset
 *
 *  @return length
 */
- (NSUInteger) parseEncryptedPart:(NSData *)data error:(NSError **)error
{
    NSUInteger position = 0;

    // If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm
    [data getBytes:&_symmetricAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // S2K
    self.s2k = [PGPString2Key string2KeyFromData:data atPosition:position];
    position = position + self.s2k.length;

    // Initial Vector (IV) of the same length as the cipher's block size
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
    NSAssert(blockSize <= 16, @"invalid blockSize");

    self.ivData = [data subdataWithRange:(NSRange) {position, blockSize}];
    position = position + blockSize;


    // encrypted MPIs
    // checksum or hash is encrypted together with the algorithm-specific fields (if string-to-key usage octet is not zero).
    self.encryptedMPIAndHashData = [data subdataWithRange:(NSRange) {position, data.length - position}];
    position = position + self.encryptedMPIAndHashData.length;

#ifdef DEBUG
    //[self decrypt:@"1234"];
    [self decrypt:@"1234" error:error];  // invalid password
#endif
    return data.length;
}

/**
 *  Cleartext part
 *
 *  @param packetBody packet data
 *  @param position   position offset
 *
 *  @return length
 */
- (NSUInteger) parseCleartextPart:(NSData *)data error:(NSError **)error
{
    NSUInteger position = 0;

    // check hash before read actual data
    // hash is physically located at the end of dataBody
    switch (self.s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed:
        {
            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:PGPHashSHA1];
            NSAssert(hashSize <= 20, @"invalid hashSize");

            NSData *clearTextData = [data subdataWithRange:(NSRange) {0, data.length - hashSize}];
            NSData *hashData = [data subdataWithRange:(NSRange){data.length - hashSize, hashSize}];
            NSData *calculatedHashData = [clearTextData SHA1];

            if (![hashData isEqualToData:calculatedHashData]) {
                if (error) {
                    *error = [NSError errorWithDomain:@"objectivepgp.hakore.com" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Decrypted hash mismatch, check password."}];
                    return data.length;
                }
            }

        }
            break;
        default:
        {
            // a two-octet checksum of the plaintext of the algorithm-specific portion
            NSUInteger checksumLength = 2;
            NSData *clearTextData = [data subdataWithRange:(NSRange) {0, data.length - checksumLength}];
            NSData *checksumData = [data subdataWithRange:(NSRange){data.length - checksumLength, checksumLength}];
            NSUInteger calculatedChecksum = [clearTextData checksum];

            UInt16 checksum = 0;
            [checksumData getBytes:&checksum length:checksumLength];
            checksum = CFSwapInt16BigToHost(checksum);

            if (checksum != calculatedChecksum) {
                if (error) {
                    *error = [NSError errorWithDomain:@"objectivepgp.hakore.com" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Decrypted hash mismatch, check password."}];
                    return data.length;
                }
            }
        }
            break;
    }

    // now read the actual data
    switch (self.algorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA secret exponent d.
            PGPMPI *mpiD = [[PGPMPI alloc] initWithData:data atPosition:position];
            mpiD.identifier = @"D";
            position = position + mpiD.length;

            // MPI of RSA secret prime value p.
            PGPMPI *mpiP = [[PGPMPI alloc] initWithData:data atPosition:position];
            mpiP.identifier = @"P";
            position = position + mpiP.length;

            // MPI of RSA secret prime value q (p < q).
            PGPMPI *mpiQ = [[PGPMPI alloc] initWithData:data atPosition:position];
            mpiQ.identifier = @"Q";
            position = position + mpiQ.length;

            // MPI of u, the multiplicative inverse of p, mod q.
            PGPMPI *mpiU = [[PGPMPI alloc] initWithData:data atPosition:position];
            mpiU.identifier = @"U";
            position = position + mpiU.length;

            self.mpi = [NSArray arrayWithObjects:mpiD, mpiP, mpiQ, mpiU, nil];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        {
            // MPI of DSA secret exponent x.
            PGPMPI *mpiX = [[PGPMPI alloc] initWithData:data atPosition:position];
            mpiX.identifier = @"X";
            position = position + mpiX.length;

            self.mpi = [NSArray arrayWithObjects:mpiX, nil];
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        {
            // MPI of Elgamal secret exponent x.
            PGPMPI *mpiX = [[PGPMPI alloc] initWithData:data atPosition:position];
            mpiX.identifier = @"X";
            position = position + mpiX.length;

            self.mpi = [NSArray arrayWithObjects:mpiX, nil];
        }
            break;
        default:
            break;
    }

    return data.length;
}

/**
 *  Decrypt parsed encrypted packet
 *  TODO: V3 support
 */
- (BOOL) decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error
{
    if (!self.isEncrypted) {
        return NO;
    }

    if (!self.ivData) {
        return NO;
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

    NSUInteger outButterLength = self.encryptedMPIAndHashData.length;
    UInt8 *outBuffer = calloc(outButterLength, sizeof(UInt8));

    NSData *decryptedData = nil;

    // decrypt with CFB
    switch (self.symmetricAlgorithm) {
        case PGPSymmetricAES128:
        case PGPSymmetricAES192:
        case PGPSymmetricAES256:
        {
            AES_KEY *encrypt_key = calloc(1, sizeof(AES_KEY));
            AES_set_encrypt_key(keyData.bytes, keySize * 8, encrypt_key);

            AES_KEY *decrypt_key = calloc(1, sizeof(AES_KEY));
            AES_set_decrypt_key(keyData.bytes, keySize * 8, decrypt_key);

            int num = 0;
            AES_cfb128_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)self.ivData.bytes, &num, AES_DECRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];

            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
        }
            break;
        case PGPSymmetricIDEA:
        {
            IDEA_KEY_SCHEDULE *encrypt_key = calloc(1, sizeof(IDEA_KEY_SCHEDULE));
            idea_set_encrypt_key(keyData.bytes, encrypt_key);

            IDEA_KEY_SCHEDULE *decrypt_key = calloc(1, sizeof(IDEA_KEY_SCHEDULE));
            idea_set_decrypt_key(encrypt_key, decrypt_key);

            int num = 0;
            idea_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)self.ivData.bytes, &num, CAST_DECRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];

            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
        }
            break;
        case PGPSymmetricTripleDES:
        {
            DES_key_schedule *keys = calloc(3, sizeof(DES_key_schedule));

            for (NSUInteger n = 0; n < 3; ++n) {
                DES_set_key((DES_cblock *)(void *)(self.ivData.bytes + n * 8),&keys[n]);
            }

            int num = 0;
            DES_ede3_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, &keys[0], &keys[1], &keys[2], (DES_cblock *)self.ivData.bytes, &num, DES_DECRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];

            if (keys) free(keys);
        }
            break;
        case PGPSymmetricCAST5:
        {
            // initialize
            CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(encrypt_key, keySize, keyData.bytes);

            CAST_KEY *decrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(decrypt_key, keySize, keyData.bytes);

            // see __ops_decrypt_init block_encrypt siv,civ,iv comments. siv is needed for weird v3 resync,
            // wtf civ ???
            // CAST_ecb_encrypt(in, out, encrypt_key, CAST_ENCRYPT);

            //TODO: maybe CommonCrypto with kCCModeCFB in place of OpenSSL
            int num = 0; //	how much of the 64bit block we have used
            CAST_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)self.ivData.bytes, &num, CAST_DECRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];

            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
        }
            break;

        default:
            break;
    }

    if (outBuffer) {
        memset(outBuffer, 0, sizeof(UInt8));
        free(outBuffer);
    }

    // now read mpis
    if (decryptedData) {
        [self parseCleartextPart:decryptedData error:error];
        if (error) {
            return NO;
        }
    }
    return YES;
}



@end
