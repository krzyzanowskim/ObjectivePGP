//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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
#import "PGPFoundation.h"

#import "NSData+PGPUtils.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"
#import "PGPRSA.h"

NS_ASSUME_NONNULL_BEGIN

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
    for (PGPMPI *mpi in self.secretMPIs) {
        if (PGPEqualObjects(mpi.identifier, identifier)) {
            return mpi;
        }
    }

    return nil;
}

- (PGPFingerprint *)fingerprint {
    return [super fingerprint];
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(packetBody, NSData);

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
    NSUInteger length = 0;
    if (self.isEncryptedWithPassphrase && [self parseEncryptedPart:encryptedData length:&length error:error]) {
        position = position + length;
    } else if ([self parseUnencryptedPart:encryptedData length:&length error:error]) {
        position = position + length;
    }

    return position;
}

/**
 *  Encrypted algorithm-specific fields for secret keys
 *
 *  @param data Encrypted data
 *  @param length Length of parsed data
 *  @param error error
 *
 *  @return YES on success.
 */
- (BOOL)parseEncryptedPart:(NSData *)data length:(NSUInteger *)length error:(NSError * __autoreleasing _Nullable *)error {
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
        self.ivData = nil;
    } else if (self.s2k.specifier == PGPS2KSpecifierDivertToCard) {
        self.ivData = NSData.data;
    } else if (self.s2kUsage != PGPS2KUsageNonEncrypted) {
        // Initial Vector (IV) of the same length as the cipher's block size
        NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:self.symmetricAlgorithm];
        if (blockSize > 16) {
            return NO;
        }
        self.ivData = [data subdataWithRange:(NSRange){position, blockSize}];
        position = position + blockSize;
    } else if (error) {
        *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Cannot export packet. Unsupported S2K setup."}];
        *length = data.length;
        return NO;
    }

    // encrypted MPIArray
    // checksum or hash is encrypted together with the algorithm-specific fields (mpis) (if string-to-key usage octet is not zero).
    self.encryptedMPIPartData = [data subdataWithRange:(NSRange){position, data.length - position}];
    // position = position + self.encryptedMPIPartData.length;

    *length = data.length;
    return YES;
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
- (BOOL)parseUnencryptedPart:(NSData *)data length:(nullable NSUInteger *)length error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = 0;

    // check hash before read actual data
    // hash is physically located at the end of dataBody
    switch (self.s2kUsage) {
        case PGPS2KUsageEncryptedAndHashed: {
            // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion.
            NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:PGPHashSHA1];
            if (hashSize == NSNotFound) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseInvalid userInfo:@{ NSLocalizedDescriptionKey: @"Decrypted hash mismatch, invalid passphrase." }];
                }
                if (length) {
                    *length = data.length;
                }
                return NO;
            }

            let clearTextData = [data subdataWithRange:(NSRange){0, data.length - hashSize}];
            let hashData = [data subdataWithRange:(NSRange){data.length - hashSize, hashSize}];
            let calculatedHashData = clearTextData.pgp_SHA1;

            if (!PGPEqualObjects(hashData,calculatedHashData)) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseInvalid userInfo:@{ NSLocalizedDescriptionKey: @"Decrypted hash mismatch, invalid passphrase." }];
                }
                if (length) {
                    *length = data.length;
                }
                return NO;
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
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Decrypted hash mismatch, check passphrase." }];
                }

                if (length) {
                    *length = data.length;
                }
                return NO;
            }
        } break;
    }

    // now read the actual data
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // multiprecision integer (MPI) of RSA secret exponent d.
            let mpiD = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierD atPosition:position];
            position = position + mpiD.packetLength;

            // MPI of RSA secret prime value p.
            let mpiP = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierP atPosition:position];
            position = position + mpiP.packetLength;

            // MPI of RSA secret prime value q (p < q).
            let mpiQ = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierQ atPosition:position];
            position = position + mpiQ.packetLength;

            // MPI of u, the multiplicative inverse of p, mod q.
            let mpiU = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierU atPosition:position];
            position = position + mpiU.packetLength;

            self.secretMPIs = @[mpiD, mpiP, mpiQ, mpiU];
        } break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmElgamal: {
            // MPI of DSA secret exponent x.
            // MPI of Elgamal secret exponent x.
            let mpiX = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierX atPosition:position];
            position = position + mpiX.packetLength;

            self.secretMPIs = @[mpiX];
        } break;
        case PGPPublicKeyAlgorithmECDSA:
        case PGPPublicKeyAlgorithmECDH: {
            let mpiEC_D = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierD atPosition:position];
            position = position + mpiEC_D.packetLength;

            self.secretMPIs = @[mpiEC_D];
        } break;
        case PGPPublicKeyAlgorithmEdDSA: {
            let mpiEC_SEED = [[PGPMPI alloc] initWithMPIData:data identifier:PGPMPIdentifierD atPosition:position];
            position = position + mpiEC_SEED.packetLength;

            self.secretMPIs = @[mpiEC_SEED];
        } break;
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        case PGPPublicKeyAlgorithmDiffieHellman:
        case PGPPublicKeyAlgorithmPrivate1:
        case PGPPublicKeyAlgorithmPrivate2:
        case PGPPublicKeyAlgorithmPrivate3:
        case PGPPublicKeyAlgorithmPrivate4:
        case PGPPublicKeyAlgorithmPrivate5:
        case PGPPublicKeyAlgorithmPrivate6:
        case PGPPublicKeyAlgorithmPrivate7:
        case PGPPublicKeyAlgorithmPrivate8:
        case PGPPublicKeyAlgorithmPrivate9:
        case PGPPublicKeyAlgorithmPrivate10:
        case PGPPublicKeyAlgorithmPrivate11:
            // noop
            position = position + data.length;
        break;
    }

    if (length) {
        *length = data.length;
    }
    return YES;
}

#pragma mark - Decrypt

/**
 *  Decrypt parsed encrypted packet
 *  Decrypt packet and store decrypted data on instance
 *  TODO: V3 support - partially supported, need testing.
 *  NOTE: Decrypted packet data should be released/forget after use
 */
- (nullable PGPSecretKeyPacket *)decryptedWithPassphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(passphrase, NSString);

    // gnu-dummy is encrypted but we can't decrypt it since the secret material is not available.
    // the best we can do is the input key
    if (!self.isEncryptedWithPassphrase || self.s2k.specifier == PGPS2KSpecifierGnuDummy) {
        PGPLogDebug(@"No need to decrypt key.");
        return self;
    }

    if (!self.ivData) {
        PGPLogError(@"IV is missing...");
        if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"IV is missing" } ]; };
        return nil;
    }

    PGPSecretKeyPacket *decryptedKeyPacket = self.copy;
    let encryptionSymmetricAlgorithm = decryptedKeyPacket.symmetricAlgorithm;

    // Session key for passphrase
    // producing a key to be used with a symmetric block cipher from a string of octets
    let sessionKeyData = [decryptedKeyPacket.s2k produceSessionKeyWithPassphrase:passphrase symmetricAlgorithm:encryptionSymmetricAlgorithm];
    if (!sessionKeyData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Can't build session key." } ];
        }
        return nil;
    }

    // Decrypted MPIArray
    let decryptedData = [PGPCryptoCFB decryptData:decryptedKeyPacket.encryptedMPIPartData sessionKeyData:sessionKeyData symmetricAlgorithm:encryptionSymmetricAlgorithm iv:decryptedKeyPacket.ivData syncCFB:NO];

    // now read mpis
    if (decryptedData) {
        [decryptedKeyPacket parseUnencryptedPart:decryptedData length:nil error:error];
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
        [data pgp_appendData:self.ivData];
    }

    if (self.s2kUsage == PGPS2KUsageNonEncrypted) {
        for (PGPMPI *mpi in self.secretMPIs) {
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

    // TODO: Verify ECC support!

    return data;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        let secretKeyPacketData = [NSMutableData data];
        [secretKeyPacketData appendData:[self buildKeyBodyDataAndForceV4:YES]];
        [secretKeyPacketData appendData:[self buildSecretKeyDataAndForceV4:YES]];
        return secretKeyPacketData;
    }];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToKeyPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToKeyPacket:(PGPSecretKeyPacket *)packet {
    return self.version == packet.version &&
        self.s2kUsage == packet.s2kUsage &&
        self.publicKeyAlgorithm == packet.publicKeyAlgorithm &&
        self.V3validityPeriod == packet.V3validityPeriod &&
        PGPEqualObjects(self.createDate, packet.createDate) &&
        PGPEqualObjects(self.publicMPIs, packet.publicMPIs) &&
        PGPEqualObjects(self.secretMPIs, packet.secretMPIs);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.version;
    result = prime * result + self.s2kUsage;
    result = prime * result + self.publicKeyAlgorithm;
    result = prime * result + self.V3validityPeriod;
    result = prime * result + self.createDate.hash;
    result = prime * result + self.publicMPIs.hash;
    result = prime * result + self.secretMPIs.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([super copyWithZone:zone], PGPSecretKeyPacket);
    duplicate.version = self.version;
    duplicate.s2kUsage = self.s2kUsage;
    duplicate.s2k = self.s2k;
    duplicate.symmetricAlgorithm = self.symmetricAlgorithm;
    duplicate.ivData = self.ivData;
    duplicate.secretMPIs = [[NSArray alloc] initWithArray:self.secretMPIs copyItems:YES];
    duplicate.encryptedMPIPartData = self.encryptedMPIPartData;;
    duplicate.wasDecrypted = self.wasDecrypted;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
