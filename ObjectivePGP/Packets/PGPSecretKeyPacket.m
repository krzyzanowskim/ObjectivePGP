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
#import "PGPSecretKeyPacket+Private.h"
#import "PGPPacket+Private.h"
#import "PGPMPI.h"
#import "PGPS2K.h"
#import "PGPTypes.h"
#import "NSMutableData+PGPUtils.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

#import "NSData+PGPUtils.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"
#import "PGPRSA.h"

@interface PGPSecretKeyPacket ()

@property (nonatomic) BOOL wasDecrypted; // is decrypted

@end

@implementation PGPSecretKeyPacket

- (PGPPacketTag)tag {
    return PGPSecretKeyPacketTag;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ isEncryptedWithPassphrase: %@", super.description, @(self.isEncryptedWithPassphrase)];
}

// Don't really know if key is passphrase protected.
// Check the S2K settings and assume if the passphrase is set.
- (BOOL)isEncryptedWithPassphrase {
    if (self.wasDecrypted) {
        return NO;
    }

    return (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed);
}

- (nullable PGPMPI *)secretMPI:(NSString *)identifier {
    for (PGPMPI *mpi in self.secretMPIArray) {
        if ([mpi.identifier isEqual:identifier]) {
            return mpi;
        }
    }

    return nil;
}

- (PGPFingerprint *)fingerprint {
    return [super fingerprint];
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    //  5.5.3.  Secret-Key Packet Formats

    NSAssert(self.version == 0x04 || self.version == 0x03, @"Only Secret Key version 3 and 4 is supported. Found version %@", @(self.version));

    // One octet indicating string-to-key usage conventions
    [packetBody getBytes:&_s2kUsage range:(NSRange){position, 1}];
    position = position + 1;

    if (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
        // moved to parseEncryptedPart:error
    } else if (self.s2kUsage != PGPS2KUsageNonEncrypted) {
        // this is version 3, looks just like a V4 simple hash
        self.symmetricAlgorithm = (PGPSymmetricAlgorithm)self.s2kUsage; // this is tricky, but this is right. V3 algorithm is in place of s2kUsage of V4
        self.s2kUsage = PGPS2KUsageEncrypted;

        self.s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSimple hashAlgorithm:PGPHashMD5]; // not really parsed s2k, overwritten in parseEncryptedPart
    }

    let encryptedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
    if (self.isEncryptedWithPassphrase) {
        position = position + [self parseEncryptedPart:encryptedData error:error];
    } else {
        position = position + [self parseUnencryptedPart:encryptedData error:error];
    }

    return position;
}

/**
 *  Encrypted algorithm-specific fields for secret keys
 *
 *  @param data Encrypted data
 *  @param error error
 *
 *  @return length
 */
- (NSUInteger)parseEncryptedPart:(NSData *)data error:(NSError *__autoreleasing *)error {
    NSUInteger position = 0;

    if (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
        // If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm
        [data getBytes:&_symmetricAlgorithm range:(NSRange){position, 1}];
        position = position + 1;

        // S2K
        NSUInteger s2kParsedLength = 0;
        self.s2k = [PGPS2K S2KFromData:data atPosition:position length:&s2kParsedLength];
        position = position + s2kParsedLength;
    }

    if (self.s2k.specifier == PGPS2KSpecifierGnuDummy) {
        self.ivData = NSData.data;
    } else if (self.s2kUsage != PGPS2KUsageNonEncrypted) {
        // Initial Vector (IV) of the same length as the cipher's block size
        NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
        NSAssert(blockSize <= 16, @"invalid blockSize");
        self.ivData = [data subdataWithRange:(NSRange){position, blockSize}];
        position = position + blockSize;
    }

    // encrypted MPIArray
    // checksum or hash is encrypted together with the algorithm-specific fields (mpis) (if string-to-key usage octet is not zero).
    self.encryptedMPIPartData = [data subdataWithRange:(NSRange){position, data.length - position}];
    // position = position + self.encryptedMPIPartData.length;

    return data.length;
}

/**
 *  Cleartext part, parse cleartext or unencrypted data
 *  Store decrypted values in secretMPI array
 *
 *  @param data packet data
 *  @param error error
 *
 *  @return length
 */
- (NSUInteger)parseUnencryptedPart:(NSData *)data error:(NSError *__autoreleasing *)error {
    NSUInteger position = 0;

    // check hash before read actual data
    // hash is physically located at the end of dataBody
    switch (self.s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed: {
            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:PGPHashSHA1];
            if (hashSize == NSNotFound) {
                PGPLogWarning(@"Invalid hash size");
                return 0;
            }

            let clearTextData = [data subdataWithRange:(NSRange){0, data.length - hashSize}];
            let hashData = [data subdataWithRange:(NSRange){data.length - hashSize, hashSize}];
            let calculatedHashData = clearTextData.pgp_SHA1;

            if (![hashData isEqualToData:calculatedHashData]) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseInvalid userInfo:@{ NSLocalizedDescriptionKey: @"Decrypted hash mismatch, invalid passphrase." }];
                    return data.length;
                }
            }

        } break;
        default: {
            // a two-octet checksum of the plaintext of the algorithm-specific portion
            NSUInteger checksumLength = 2;
            let clearTextData = [data subdataWithRange:(NSRange){0, data.length - checksumLength}];
            let checksumData = [data subdataWithRange:(NSRange){data.length - checksumLength, checksumLength}];
            NSUInteger calculatedChecksum = clearTextData.pgp_Checksum;

            UInt16 checksum = 0;
            [checksumData getBytes:&checksum length:checksumLength];
            checksum = CFSwapInt16BigToHost(checksum);

            if (checksum != calculatedChecksum) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:-1 userInfo:@{ NSLocalizedDescriptionKey: @"Decrypted hash mismatch, check passphrase." }];
                    return data.length;
                }
            }
        } break;
    }

    // now read the actual data
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // multiprecision integer (MPI) of RSA secret exponent d.
            let mpiD = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPI_D atPosition:position];
            position = position + mpiD.packetLength;

            // MPI of RSA secret prime value p.
            let mpiP = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPI_P atPosition:position];
            position = position + mpiP.packetLength;

            // MPI of RSA secret prime value q (p < q).
            let mpiQ = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPI_Q atPosition:position];
            position = position + mpiQ.packetLength;

            // MPI of u, the multiplicative inverse of p, mod q.
            let mpiU = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPI_U atPosition:position];
            position = position + mpiU.packetLength;

            self.secretMPIArray = @[mpiD, mpiP, mpiQ, mpiU];
        } break;
        case PGPPublicKeyAlgorithmDSA: {
            // MPI of DSA secret exponent x.
            let mpiX = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPI_X atPosition:position];
            position = position + mpiX.packetLength;

            self.secretMPIArray = @[mpiX];
        } break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign: {
            // MPI of Elgamal secret exponent x.
            let mpiX = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPI_X atPosition:position];
            position = position + mpiX.packetLength;

            self.secretMPIArray = @[mpiX];
        } break;
        default:
            break;
    }

    return data.length;
}

#pragma mark - Decrypt

/**
 *  Decrypt parsed encrypted packet
 *  Decrypt packet and store decrypted data on instance
 *  TODO: V3 support - partially supported, need testing.
 *  NOTE: Decrypted packet data should be released/forget after use
 */
- (nullable PGPSecretKeyPacket *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError *__autoreleasing *)error {
    PGPAssertClass(passphrase, NSString);
    NSParameterAssert(error);

    if (!self.isEncryptedWithPassphrase) {
        PGPLogDebug(@"No need to decrypt key.");
        return self;
    }

    if (!self.ivData) {
        PGPLogError(@"IV is missing...");
        if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"IV is missing" } ]; };
        return nil;
    }

    PGPSecretKeyPacket *decryptedKeyPacket = self.copy;
    let encryptionSymmetricAlgorithm = decryptedKeyPacket.symmetricAlgorithm;

    // Session key for passphrase
    // producing a key to be used with a symmetric block cipher from a string of octets
    let sessionKeyData = [decryptedKeyPacket.s2k produceSessionKeyWithPassphrase:passphrase symmetricAlgorithm:encryptionSymmetricAlgorithm];

    // Decrypted MPIArray
    let decryptedData = [PGPCryptoCFB decryptData:decryptedKeyPacket.encryptedMPIPartData sessionKeyData:sessionKeyData symmetricAlgorithm:encryptionSymmetricAlgorithm iv:decryptedKeyPacket.ivData];

    // now read mpis
    if (decryptedData) {
        [decryptedKeyPacket parseUnencryptedPart:decryptedData error:error];
        if (*error) {
            return nil;
        }
    }
    decryptedKeyPacket.wasDecrypted = YES;
    return decryptedKeyPacket;
}

#pragma mark - Private

/**
 *  Build public key data for fingerprint
 *
 *  @return public key data starting with version octet
 */
- (NSData *)buildSecretKeyDataAndForceV4:(BOOL)forceV4 {
    NSAssert(forceV4 == YES, @"Only V4 is supported");

    let data = [NSMutableData data];
    [data appendBytes:&self->_s2kUsage length:1];

    if (self.s2kUsage == PGPS2KUsageEncrypted || self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
        // If string-to-key usage octet was 255 or 254, a one-octet symmetric encryption algorithm
        [data appendBytes:&self->_symmetricAlgorithm length:1];

        // If string-to-key usage octet was 255 or 254, a string-to-key specifier.
        NSError *exportError = nil;
        let exportS2K = [self.s2k export:&exportError];
        [data pgp_appendData:exportS2K];
        NSAssert(!exportError, @"export failed");
    }

    if (self.s2kUsage != PGPS2KUsageNonEncrypted) {
        NSAssert(self.ivData, @"Require IV");
        // If secret data is encrypted (string-to-key usage octet not zero), an Initial Vector (IV) of the same length as the cipher's block size.
        // Initial Vector (IV) of the same length as the cipher's block size
        [data appendData:self.ivData];
    }

    if (self.s2kUsage == PGPS2KUsageNonEncrypted) {
        for (PGPMPI *mpi in self.secretMPIArray) {
            let exportMPI = [mpi exportMPI];
            [data pgp_appendData:exportMPI];
        }

        // append hash
        UInt16 checksum = CFSwapInt16HostToBig(data.pgp_Checksum);
        [data appendBytes:&checksum length:2];
    } else if (self.encryptedMPIPartData) {
        // encrypted MPIArray with encrypted hash
        // hash is part of encryptedMPIPartData
        [data pgp_appendData:self.encryptedMPIPartData];
    } else {
        PGPLogWarning(@"Cannot build secret key data. Missing secret MPIs....");
    }

    // If the string-to-key usage octet is zero or 255, then a two-octet checksum of the plaintext of the algorithm-specific portion (sum of all octets, mod 65536).
    // This checksum or hash is encrypted together with the algorithm-specific fields
    // ---> is part of self.encryptedMPIPartData
    // if (self.s2kUsage == PGPS2KUsageNonEncrypted || self.s2kUsage == PGPS2KUsageEncrypted) {
    //    // Checksum
    //    UInt16 checksum = CFSwapInt16HostToBig([data pgp_Checksum]);
    //    [data appendBytes:&checksum length:2];
    //} else if (self.s2kUsage == PGPS2KUsageEncryptedAndHashed) {
    //    // If the string-to-key usage octet was 254, then a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
    //    [data appendData:[data pgp_SHA1]];
    //}

    //    } else if (self.s2kUsage != PGPS2KUsageNonEncrypted) {
    //        // this is version 3, looks just like a V4 simple hash
    //        self.symmetricAlgorithm = (PGPSymmetricAlgorithm)self.s2kUsage; // this is tricky, but this is right. V3 algorithm is in place of s2kUsage of V4
    //        self.s2kUsage = PGPS2KUsageEncrypted;
    //
    //        self.s2k = [[PGPS2K alloc] init]; // not really parsed s2k
    //        self.s2k.specifier = PGPS2KSpecifierSimple;
    //        self.s2k.algorithm = PGPHashMD5;

    return data;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error {
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        let secretKeyPacketData = [NSMutableData data];
        [secretKeyPacketData appendData:[self buildKeyBodyData:YES]];
        [secretKeyPacketData appendData:[self buildSecretKeyDataAndForceV4:YES]];
        return  secretKeyPacketData;
    }];

    //TODO: to be removed when verified
    //    let data = [NSMutableData data];
    //    let publicKeyData = [super buildKeyBodyData:YES];
    //
    //    let secretKeyPacketData = [NSMutableData data];
    //    [secretKeyPacketData appendData:publicKeyData];
    //    [secretKeyPacketData appendData:[self buildSecretKeyDataAndForceV4:YES]];
    //    if (!self.bodyData) {
    //        self.bodyData = secretKeyPacketData;
    //    }
    //
    //    let headerData = [self buildHeaderData:secretKeyPacketData];
    //    if (!self.headerData) {
    //        self.headerData = headerData;
    //    }
    //    [data appendData:headerData];
    //    [data appendData:secretKeyPacketData];
    //
    //    // header not always match because export new format while input can be old format
    //    NSAssert(!self.bodyData || [secretKeyPacketData isEqualToData:self.bodyData], @"Secret key doesn't match");
    //    return data;
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    let copy = PGPCast([super copyWithZone:zone], PGPSecretKeyPacket);
    copy->_s2kUsage = self.s2kUsage;
    copy->_s2k = [self.s2k copy];
    copy->_symmetricAlgorithm = self.symmetricAlgorithm;
    copy->_ivData = [self.ivData copy];
    copy->_secretMPIArray = [self.secretMPIArray copy];
    copy->_encryptedMPIPartData = [self.encryptedMPIPartData copy];
    copy->_wasDecrypted = self.wasDecrypted;
    return copy;
}

@end
