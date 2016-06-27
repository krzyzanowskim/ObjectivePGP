//
//  PGPSecretKeyPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  A Secret-Key packet contains all the information that is found in a
//  Public-Key packet, including the public-key material, but also
//  includes the secret-key material after all the public-key fields.

#import "PGPSecretKeyPacket.h"
#import "PGPS2K.h"
#import "PGPMPI.h"
#import "PGPTypes.h"

#import "PGPCryptoUtils.h"
#import "NSData+PGPUtils.h"
#import "PGPCryptoCFB.h"
#import "PGPPublicKeyRSA.h"

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

@interface PGPPacket ()
@property (copy, readwrite) NSData *headerData;
@property (copy, readwrite) NSData *bodyData;
@end

@interface PGPSecretKeyPacket ()
@property (strong, readwrite) NSData *encryptedMPIsPartData; // after decrypt -> secretMPIArray
@property (strong, readwrite) NSData *ivData;
@property (strong, readwrite) NSArray *secretMPIArray; // decrypted MPI

@property (assign, readwrite) BOOL wasDecrypted; // is decrypted
@end

@implementation PGPSecretKeyPacket

- (PGPPacketTag)tag
{
    return PGPSecretKeyPacketTag;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ isEncrypted: %@", [super description], @(self.isEncryptedWithPassword)];
}

- (BOOL)isEncryptedWithPassword
{
    if (self.wasDecrypted) {
        return NO;
    }
    
    return (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed);
}

- (PGPMPI *) secretMPI:(NSString *)identifier
{
    __block PGPMPI *returnMPI = nil;
    [self.secretMPIArray enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        PGPMPI *mpi = obj;
        if ([mpi.identifier isEqualToString:identifier]) {
            returnMPI = mpi;
            *stop = YES;
        }
    }];

    return returnMPI;
}

- (PGPFingerprint *)fingerprint
{
    return [super fingerprint];
}

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];
    NSData *publicKeyData = [super buildPublicKeyBodyData:YES];

    NSMutableData *secretKeyPacketData = [NSMutableData data];
    [secretKeyPacketData appendData:publicKeyData];
    [secretKeyPacketData appendData:[self buildSecretKeyDataAndForceV4:YES]];

    NSData *headerData = [self buildHeaderData:secretKeyPacketData];
    [data appendData: headerData];
    [data appendData: secretKeyPacketData];

    // header not allways match because export new format while input can be old format
    NSAssert([secretKeyPacketData isEqualToData:self.bodyData], @"Secret key not match");
    return [data copy];
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
        // moved to parseEncryptedPart:error
    } else if (self.s2kUsage != PGPS2KUsageNone) {
        // this is version 3, looks just like a V4 simple hash
        self.symmetricAlgorithm = (PGPSymmetricAlgorithm)self.s2kUsage; // this is tricky, but this is right. V3 algorithm is in place of s2kUsage of V4
        self.s2kUsage = PGPS2KUsageEncrypted;
        
        self.s2k = [[PGPS2K alloc] init]; // not really parsed s2k
        self.s2k.specifier = PGPS2KSpecifierSimple;
        self.s2k.hashAlgorithm = PGPHashMD5;
    }

    NSData *encryptedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
    if (self.isEncryptedWithPassword) {
        position = position + [self parseEncryptedPart:encryptedData error:error];
    } else {
        position = position + [self parseUnencryptedPart:encryptedData error:error];
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
- (NSUInteger) parseEncryptedPart:(NSData *)data error:(NSError * __autoreleasing *)error
{
    NSUInteger position = 0;

    if (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
        // If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm
        [data getBytes:&_symmetricAlgorithm range:(NSRange){position, 1}];
        position = position + 1;

        // S2K
        self.s2k = [PGPS2K string2KeyFromData:data atPosition:position];
        position = position + self.s2k.length;
    }

    if (self.s2kUsage != PGPS2KUsageNone) {
        // Initial Vector (IV) of the same length as the cipher's block size
        NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
        NSAssert(blockSize <= 16, @"invalid blockSize");
        self.ivData = [data subdataWithRange:(NSRange) {position, blockSize}];
        position = position + blockSize;
    }

    // encrypted MPIs
    // checksum or hash is encrypted together with the algorithm-specific fields (mpis) (if string-to-key usage octet is not zero).
    self.encryptedMPIsPartData = [data subdataWithRange:(NSRange) {position, data.length - position}];
    position = position + self.encryptedMPIsPartData.length;

    return data.length;
}

/**
 *  Cleartext part, parse cleartext or unencrypted data
 *  Store decrypted values in secretMPI array
 *
 *  @param packetBody packet data
 *  @param position   position offset
 *
 *  @return length
 */
- (NSUInteger) parseUnencryptedPart:(NSData *)data error:(NSError * __autoreleasing *)error
{
    __unused NSUInteger position = 0;

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
            NSData *calculatedHashData = [clearTextData pgp_SHA1];

            if (![hashData isEqualToData:calculatedHashData]) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseInvalid userInfo:@{NSLocalizedDescriptionKey: @"Decrypted hash mismatch, invalid password."}];
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
            NSUInteger calculatedChecksum = [clearTextData pgp_Checksum];

            UInt16 checksum = 0;
            [checksumData getBytes:&checksum length:checksumLength];
            checksum = CFSwapInt16BigToHost(checksum);

            if (checksum != calculatedChecksum) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Decrypted hash mismatch, check password."}];
                    return data.length;
                }
            }
        }
            break;
    }

    // now read the actual data
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA secret exponent d.
            PGPMPI *mpiD = [[PGPMPI alloc] initWithMPIData:data atPosition:position];
            mpiD.identifier = @"D";
            position = position + mpiD.packetLength;

            // MPI of RSA secret prime value p.
            PGPMPI *mpiP = [[PGPMPI alloc] initWithMPIData:data atPosition:position];
            mpiP.identifier = @"P";
            position = position + mpiP.packetLength;

            // MPI of RSA secret prime value q (p < q).
            PGPMPI *mpiQ = [[PGPMPI alloc] initWithMPIData:data atPosition:position];
            mpiQ.identifier = @"Q";
            position = position + mpiQ.packetLength;

            // MPI of u, the multiplicative inverse of p, mod q.
            PGPMPI *mpiU = [[PGPMPI alloc] initWithMPIData:data atPosition:position];
            mpiU.identifier = @"U";
            position = position + mpiU.packetLength;

            self.secretMPIArray = @[mpiD, mpiP, mpiQ, mpiU];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        {
            // MPI of DSA secret exponent x.
            PGPMPI *mpiX = [[PGPMPI alloc] initWithMPIData:data atPosition:position];
            mpiX.identifier = @"X";
            position = position + mpiX.packetLength;

            self.secretMPIArray = @[mpiX];
        }
            break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        {
            // MPI of Elgamal secret exponent x.
            PGPMPI *mpiX = [[PGPMPI alloc] initWithMPIData:data atPosition:position];
            mpiX.identifier = @"X";
            position = position + mpiX.packetLength;

            self.secretMPIArray = @[mpiX];
        }
            break;
        default:
            break;
    }

    return data.length;
}

/**
 *  Decrypt parsed encrypted packet
 *  Decrypt packet and store decrypted data on instance
 *  TODO: V3 support - partially supported, need testing.
 *  NOTE: Decrypted packet data should be released/forget after use
 */
- (PGPSecretKeyPacket *) decryptedKeyPacket:(NSString *)passphrase error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(passphrase);
    NSParameterAssert(error);

    if (!self.isEncryptedWithPassword) {
        return self;
    }

    if (!self.ivData) {
        return nil;
    }

    PGPSecretKeyPacket *encryptedKey = [self copy];

    // Keysize
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:encryptedKey.symmetricAlgorithm];
    NSAssert(keySize <= 32, @"invalid keySize");

    // Session key for password
    // producing a key to be used with a symmetric block cipher from a string of octets
    NSData *sessionKeyData = [encryptedKey.s2k produceSessionKeyWithPassphrase:passphrase keySize:keySize];

    // Decrypted MPIs
    NSData *decryptedData = [PGPCryptoCFB decryptData:encryptedKey.encryptedMPIsPartData
                                       sessionKeyData:sessionKeyData
                                   symmetricAlgorithm:self.symmetricAlgorithm
                                                   iv:encryptedKey.ivData];


    // now read mpis
    if (decryptedData) {
        [encryptedKey parseUnencryptedPart:decryptedData error:error];
        if (*error) {
            return nil;
        }
    }
    encryptedKey.wasDecrypted = YES;
    return encryptedKey;
}

#pragma mark - Decrypt

- (NSData *) decryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm
{
    switch (publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // return decrypted m
            return [PGPPublicKeyRSA privateDecrypt:data withSecretKeyPacket:self];
        }
            break;
        default:
            //TODO: add algorithms
            [NSException raise:@"PGPNotSupported" format:@"Algorith not supported"];
            break;
    }
    return nil;
}

#pragma mark - Private

/**
 *  Build public key data for fingerprint
 *
 *  @return public key data starting with version octet
 */
- (NSData *) buildSecretKeyDataAndForceV4:(BOOL)forceV4
{
    NSAssert(forceV4 == YES,@"Only V4 is supported");

    NSMutableData *data = [NSMutableData data];
    [data appendBytes:&_s2kUsage length:1];

    if (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
        // If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm
        [data appendBytes:&_symmetricAlgorithm length:1];

        // If string-to-key usage octet was 255 or 254, a string-to-key specifier.
        NSError *exportError = nil;
        [data appendData:[self.s2k export:&exportError]];
        NSAssert(exportError == nil, @"export failed");
    }

    if (self.s2kUsage != PGPS2KUsageNone) {
        // If secret data is encrypted (string-to-key usage octet not zero), an Initial Vector (IV) of the same length as the cipher's block size.
        // Initial Vector (IV) of the same length as the cipher's block size
        [data appendBytes:self.ivData.bytes length:self.ivData.length];
    }

    if (self.s2kUsage == PGPS2KUsageNone) {
        for (PGPMPI *mpi in self.secretMPIArray) {
            [data appendData:[mpi exportMPI]];
        }

        // append hash
        UInt16 checksum = CFSwapInt16HostToBig([data pgp_Checksum]);
        [data appendBytes:&checksum length:2];
    } else {
        // encrypted MPIs with encrypted hash
        [data appendData:self.encryptedMPIsPartData];

        // hash is part of encryptedMPIsPartData
    }

    // If the string-to-key usage octet is zero or 255, then a two-octet checksum of the plaintext of the algorithm-specific portion (sum of all octets, mod 65536).
    // This checksum or hash is encrypted together with the algorithm-specific fields
    // ---> is part of self.encryptedMPIsPartData
    //if (self.s2kUsage == PGPS2KUsageNone || self.s2kUsage == PGPS2KUsageEncrypted) {
    //    // Checksum
    //    UInt16 checksum = CFSwapInt16HostToBig([data pgp_Checksum]);
    //    [data appendBytes:&checksum length:2];
    //} else if (self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
    //    // If the string-to-key usage octet was 254, then a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
    //    [data appendData:[data pgp_SHA1]];
    //}


//    } else if (self.s2kUsage != PGPS2KUsageNone) {
//        // this is version 3, looks just like a V4 simple hash
//        self.symmetricAlgorithm = (PGPSymmetricAlgorithm)self.s2kUsage; // this is tricky, but this is right. V3 algorithm is in place of s2kUsage of V4
//        self.s2kUsage = PGPS2KUsageEncrypted;
//
//        self.s2k = [[PGPS2K alloc] init]; // not really parsed s2k
//        self.s2k.specifier = PGPS2KSpecifierSimple;
//        self.s2k.algorithm = PGPHashMD5;



    return [data copy];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone
{
    PGPSecretKeyPacket *copy = [super copyWithZone:zone];
    copy->_s2kUsage = self.s2kUsage;
    copy->_s2k = self.s2k;
    copy->_symmetricAlgorithm = self.symmetricAlgorithm;
    copy->_ivData = self.ivData;
    copy->_secretMPIArray = self.secretMPIArray;
    copy->_encryptedMPIsPartData = self.encryptedMPIsPartData;
    return copy;
}

@end
