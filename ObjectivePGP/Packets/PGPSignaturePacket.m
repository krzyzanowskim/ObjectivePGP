//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPSignaturePacket.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPKey.h"
#import "PGPLiteralPacket.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"
#import "PGPPartialKey.h"
#import "PGPRSA.h"
#import "PGPDSA.h"
#import "PGPEC.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSignatureSubpacket.h"
#import "PGPSignatureSubpacket+Private.h"
#import "PGPSignatureSubpacketHeader.h"
#import "PGPUser.h"
#import "PGPUserIDPacket.h"
#import "PGPS2K.h"
#import "PGPFoundation.h"
#import "NSMutableData+PGPUtils.h"
#import "NSArray+PGPUtils.h"
#import "NSData+PGPUtils.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

#import <openssl/bn.h>
#import <openssl/dsa.h>
#import <openssl/err.h>
#import <openssl/rsa.h>
#import <openssl/ssl.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignaturePacket ()

- (instancetype)init NS_DESIGNATED_INITIALIZER;

@end

@implementation PGPSignaturePacket

- (instancetype)init {
    if (self = [super init]) {
        _version = 0x04;
        _type = PGPSignatureUnknown;
        _hashAlgoritm = PGPHashUnknown;
        _hashedSubpackets = [NSArray<PGPSignatureSubpacket *> array];
        _unhashedSubpackets = [NSArray<PGPSignatureSubpacket *> array];
        _signatureMPIs = [NSArray<PGPMPI *> array];
    }
    return self;
}

+ (PGPSignaturePacket *)signaturePacket:(PGPSignatureType)type hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm {
    let signaturePacket = [[PGPSignaturePacket alloc] init];
    signaturePacket.type = type;
    signaturePacket.hashAlgoritm = hashAlgorithm;
    return signaturePacket;
}

- (PGPPacketTag)tag {
    return PGPSignaturePacketTag;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToSignaturePacket:other];
    }
    return NO;
}

- (BOOL)isEqualToSignaturePacket:(PGPSignaturePacket *)packet {
    return self.version == packet.version &&
            self.publicKeyAlgorithm == packet.publicKeyAlgorithm &&
            self.hashAlgoritm == packet.hashAlgoritm &&
            PGPEqualObjects(self.signedHashValueData, packet.signedHashValueData) &&
            PGPEqualObjects(self.signatureMPIs, packet.signatureMPIs) &&
            PGPEqualObjects(self.hashedSubpackets, packet.hashedSubpackets) &&
            PGPEqualObjects(self.unhashedSubpackets, packet.unhashedSubpackets);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.version;
    result = prime * result + self.type;
    result = prime * result + self.publicKeyAlgorithm;
    result = prime * result + self.hashAlgoritm;
    result = prime * result + self.signedHashValueData.hash;
    result = prime * result + self.signatureMPIs.hash;
    result = prime * result + self.hashedSubpackets.hash;
    result = prime * result + self.unhashedSubpackets.hash;
    return result;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([super copyWithZone:zone], PGPSignaturePacket);
    PGPAssertClass(duplicate, PGPSignaturePacket)
    duplicate.version = self.version;
    duplicate.type = self.type;
    duplicate.publicKeyAlgorithm = self.publicKeyAlgorithm;
    duplicate.hashAlgoritm = self.hashAlgoritm;
    duplicate.signedHashValueData = self.signedHashValueData;
    duplicate.signatureMPIs = [[NSArray alloc] initWithArray:self.signatureMPIs copyItems:YES];
    duplicate.hashedSubpackets = [[NSArray alloc] initWithArray:self.hashedSubpackets copyItems:YES];
    duplicate.unhashedSubpackets = [[NSArray alloc] initWithArray:self.unhashedSubpackets copyItems:YES];
    return duplicate;
}

#pragma mark - Helper properties

- (nullable PGPKeyID *)issuerKeyID {
    let subpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeIssuerKeyID] firstObject];
    return PGPCast(subpacket.value, PGPKeyID);
}

- (NSArray<PGPSignatureSubpacket *> *)subpackets {
    return [self.hashedSubpackets arrayByAddingObjectsFromArray:self.unhashedSubpackets ?: @[]];
}

- (NSArray<PGPSignatureSubpacket *> *)subpacketsOfType:(PGPSignatureSubpacketType)type {
    let filteredSubpackets = [NSMutableArray<PGPSignatureSubpacket *> array];
    for (PGPSignatureSubpacket *subPacket in self.subpackets) {
        if ((subPacket.type & 0x7F) == type) {
            [filteredSubpackets addObject:subPacket];
        }
    }
    return filteredSubpackets;
}

// Signature expiration date.
// Note: this is not a key expiration date.
- (nullable NSDate *)expirationDate {
    let _Nullable creationDate = self.creationDate;
    if (!creationDate) {
        return nil;
    }

    let _Nullable validityPeriodSubpacket = PGPCast([self subpacketsOfType:PGPSignatureSubpacketTypeSignatureExpirationTime].firstObject, PGPSignatureSubpacket);
    let _Nullable validityPeriod = PGPCast(validityPeriodSubpacket.value, NSNumber);
    if (!validityPeriod || validityPeriod.unsignedIntegerValue == 0) {
        return nil;
    }

    return [creationDate dateByAddingTimeInterval:validityPeriod.unsignedIntegerValue];
}

- (NSTimeInterval)keyExpirationTimeInterval {
  let _Nullable validityPeriodSubpacket = PGPCast([self subpacketsOfType:PGPSignatureSubpacketTypeKeyExpirationTime].firstObject, PGPSignatureSubpacket);
  let _Nullable validityPeriod = PGPCast(validityPeriodSubpacket.value, NSNumber);
  if (!validityPeriod || validityPeriod.unsignedIntegerValue == 0) {
    return NSNotFound;
  }

  return validityPeriod.doubleValue;
}

/// Checks signature expiration. NOT key expiration.
- (BOOL)isExpired {
    // is no expiration date then signature never expires
    let _Nullable expirationDate = self.expirationDate;
    if (!expirationDate) {
        return NO;
    }

    if ([expirationDate compare:NSDate.date] == NSOrderedAscending) {
        return YES;
    }
    return NO;
}

- (nullable NSDate *)creationDate {
    let creationDateSubpacket = PGPCast([[self subpacketsOfType:PGPSignatureSubpacketTypeSignatureCreationTime] lastObject], PGPSignatureSubpacket);
    return PGPCast(creationDateSubpacket.value, NSDate);
}

- (BOOL)isPrimaryUserID {
    let primaryUserIDSubpacket = PGPCast([[self subpacketsOfType:PGPSignatureSubpacketTypePrimaryUserID] firstObject], PGPSignatureSubpacket);
    return PGPCast(primaryUserIDSubpacket.value, NSNumber).boolValue;
}

- (BOOL)canBeUsedToSign {
    BOOL result = self.publicKeyAlgorithm != PGPPublicKeyAlgorithmRSAEncryptOnly
               && self.publicKeyAlgorithm != PGPPublicKeyAlgorithmElgamal
               && self.publicKeyAlgorithm != PGPPublicKeyAlgorithmECDH;

    if (result) {
        PGPSignatureSubpacket *subpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeKeyFlags] firstObject];
        NSArray<NSNumber *> * _Nullable flags = PGPCast(subpacket.value, NSArray);
        if ([flags containsObject:@(PGPSignatureFlagAllowSignData)]) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)canBeUsedToEncrypt {
    BOOL result = NO;
    let subpacket = PGPCast([[self subpacketsOfType:PGPSignatureSubpacketTypeKeyFlags] firstObject], PGPSignatureSubpacket);
    if (subpacket != nil) {
      // Check if subpackets allows for encryption
      NSArray<NSNumber *> * _Nullable subpacketFlags = PGPCast(subpacket.value, NSArray);
      if ([subpacketFlags containsObject:@(PGPSignatureFlagAllowEncryptStorage)] || [subpacketFlags containsObject:@(PGPSignatureFlagAllowEncryptCommunications)]) {
          result = YES;
      }
    } else {
      // Check self flags for whether encryption for main key is allowed (by excluding known sign-only options because it's short list)
      result = self.publicKeyAlgorithm != PGPPublicKeyAlgorithmRSASignOnly &&
               self.publicKeyAlgorithm != PGPPublicKeyAlgorithmElgamalEncryptorSign;
               // While it may be disputable if DSA should be included in the list: It shouldn't - DSA is not sign-only
    }

    result = result && self.publicKeyAlgorithm != PGPPublicKeyAlgorithmRSASignOnly &&
                       self.publicKeyAlgorithm != PGPPublicKeyAlgorithmElgamalEncryptorSign;
                       // While it may be disputable if DSA should be included in the list: It shouldn't - DSA is not sign-only

    return result;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, issuerKeyID: %@, canBeUsedToSign: %@, canBeUsedToEncrypt: %@", super.description, self.issuerKeyID,  @(self.canBeUsedToSign), @(self.canBeUsedToEncrypt)];
}

- (nullable PGPMPI *)signatureMPI:(NSString *)identifier {
    for (PGPMPI *mpi in self.signatureMPIs) {
        if (PGPEqualObjects(mpi.identifier, identifier)) {
            return mpi;
        }
    }

    return nil;
}

#pragma mark - Build packet

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return [self buildFullSignatureBodyData];
    }];
}

- (NSData *)buildSignedPart:(NSArray *)hashedSubpackets {
    let data = [NSMutableData data];

    // One-octet version number (4).
    UInt8 exportVersion = 0x04;
    [data appendBytes:&exportVersion length:1];

    // One-octet signature type.
    [data appendBytes:&_type length:1];

    // One-octet public-key algorithm.
    [data appendBytes:&_publicKeyAlgorithm length:1];

    // One-octet hash algorithm.
    [data appendBytes:&_hashAlgoritm length:1];

    // hashed Subpackets
    [data appendData:[PGPSignaturePacket buildSubpacketsCollectionData:hashedSubpackets]];

    return data;
}

- (nullable NSData *)buildFullSignatureBodyData {
    let data = [NSMutableData data];

    // hashed Subpackets
    let signedPartData = [self buildSignedPart:self.hashedSubpackets];
    [data appendData:signedPartData];

    // unhashed Subpackets
    [data appendData:[PGPSignaturePacket buildSubpacketsCollectionData:self.unhashedSubpackets]];

    // signed hash value
    if (!self.signedHashValueData) {
        PGPLogError(@"Missing signed hash for the signature.");
        return nil;
    }
    [data pgp_appendData:self.signedHashValueData];

    // signed PGPMPIdentifierM
    if (self.signatureMPIs.count == 0) {
        PGPLogError(@"Missing MPI for the signature.");
        return nil;
    }

    for (PGPMPI *mpi in self.signatureMPIs) {
        let exportMPI = [mpi exportMPI];
        [data pgp_appendData:exportMPI];
    }

    return data;
}

- (NSData *)calculateSignedHashForDataToSign:(NSData *)dataToSign {
    // The concatenation of the data being signed and the signature data
    // from the version number through the hashed subpacket data (inclusive)
    // is hashed.
    // toHash = toSignData + signedPartData + trailerData;
    let finalToHashData = [NSMutableData dataWithData:dataToSign];

    let signedPartData = [self buildSignedPart:self.hashedSubpackets];
    [finalToHashData appendData:signedPartData];

    let _Nullable trailerData = [self calculateTrailerFor:signedPartData];
    [finalToHashData appendData:trailerData];

    // Calculate hash value
    return [finalToHashData pgp_HashedWithAlgorithm:self.hashAlgoritm];
}

#pragma mark - Verify

- (BOOL)verifyData:(NSData *)inputData publicKey:(PGPKey *)publicKey error:(NSError * __autoreleasing _Nullable *)error {
    return [self verifyData:inputData publicKey:publicKey signingKeyPacket:(PGPPublicKeyPacket *)[publicKey.publicKey signingKeyPacketWithKeyID:self.issuerKeyID] userID:nil error:error];
}

- (BOOL)verifyData:(NSData *)inputData publicKey:(PGPKey *)publicKey userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error {
    return [self verifyData:inputData publicKey:publicKey signingKeyPacket:(PGPPublicKeyPacket *)[publicKey.publicKey signingKeyPacketWithKeyID:self.issuerKeyID] userID:userID error:error];
}

// Opposite to sign, with readed data (not produced)
- (BOOL)verifyData:(NSData *)inputData publicKey:(PGPKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error {
    // no signing packet was found, this we have no valid signature
    PGPAssertClass(inputData, NSData);
    PGPAssertClass(publicKey, PGPKey);
    PGPAssertClass(signingKeyPacket, PGPPublicKeyPacket);

    if (self.type == PGPSignatureBinaryDocument && inputData.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Invalid signature packet type" }];
        }
        return NO;
    }

    // 5.2.4.  Computing Signatures

    // build toSignData, toSign
    let toSignData = [self buildDataToSignForType:self.type inputData:inputData key:publicKey subKey:nil userID:userID error:error];
    if (!toSignData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Invalid signature." }];
        }
        return NO;
    }

    /// Calculate hash to compare
    // signedPartData
    let signedPartData = [self buildSignedPart:self.hashedSubpackets];
    // calculate trailer
    let trailerData = [self calculateTrailerFor:signedPartData];

    // toHash = toSignData + signedPartData + trailerData;
    let toHashData = [NSMutableData dataWithData:toSignData];
    [toHashData appendData:signedPartData];
    [toHashData appendData:trailerData];
    
    let hashedData = [toHashData pgp_HashedWithAlgorithm:self.hashAlgoritm];

    // TODO: Investigate how to handle V3 scenario here
    // check signed hash value, should match
    
    if (self.version == 0x04) {
        // Calculate hash value
        let calculatedHashValueData = [hashedData subdataWithRange:(NSRange){0, 2}];

        if (!PGPEqualObjects(self.signedHashValueData, calculatedHashValueData)) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Verification failed. Signature hash validation failed." }];
            }
            return NO;
        }
    }

    switch (signingKeyPacket.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSASignOnly:
        case PGPPublicKeyAlgorithmRSAEncryptOnly: {
            // convert mpi data to binary signature_bn_bin
            let signatureMPI = [self signatureMPI:PGPMPIdentifierN]; // self.signatureMPIs[0];

            // encoded m value
            let _Nullable encryptedEmData = [signatureMPI bodyData];
            // decrypted encoded m value
            let _Nullable decryptedEmData = [PGPRSA publicDecrypt:encryptedEmData withPublicKeyPacket:signingKeyPacket];

            // calculate EM and compare with decrypted EM. PKCS-emsa Encoded M.
            let keySize = ([signingKeyPacket publicMPI:PGPMPIdentifierN].bigNum.bitsCount + 7) / 8; // ks;
            let emData = [PGPPKCSEmsa encode:self.hashAlgoritm message:toHashData encodedMessageLength:keySize error:error];
            if (!PGPEqualObjects(emData, decryptedEmData)) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"em hash dont match" }];
                }
                return NO;
            }
        } break;
        case PGPPublicKeyAlgorithmDSA:{
            // fixes issue where the data to hash was being verified by PGPDSA  (always resulting in a failure)
            //  rather than the hash of the Data.
            return [PGPDSA verify:hashedData signature:self withPublicKeyPacket:signingKeyPacket error:error];
        } break;
        case PGPPublicKeyAlgorithmEdDSA: {
            return [PGPEC verify:toHashData signature:self withPublicKeyPacket:signingKeyPacket withHashAlgorithm:self.hashAlgoritm];
        } break;
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmECDSA:
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
            PGPLogWarning(@"Algorithm %@ is not supported.", @(signingKeyPacket.publicKeyAlgorithm));
            return NO;
        break;
    }

    return YES;
}

- (BOOL)verifyCertificateSignature:(PGPKey*)publicKey rootCert:(PGPKey*)rootKey userID:(nullable NSString*)userID error:(NSError* __autoreleasing _Nullable*) error {
    PGPAssertClass(publicKey, PGPKey);
    PGPAssertClass(rootKey, PGPKey);
    PGPAssertClass(userID, NSString);
    
    let signingKeyPacket = (PGPPublicKeyPacket*)[rootKey.publicKey signingKeyPacketWithKeyID:rootKey.publicKey.keyID];
    
    let toSignData = [self buildDataToVerifyForType:self.type key:publicKey userID:userID error:error];
    if (!toSignData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Invalid signature." }];
        }
        return NO;
    }
    
    /// Calculate hash to compare
    // signedPartData
    let signedPartData = [self buildSignedPart:self.hashedSubpackets];
    // calculate trailer
    let trailerData = [self calculateTrailerFor:signedPartData];
    
    // toHash = toSignData + signedPartData + trailerData;
    let toHashData = [NSMutableData dataWithData:toSignData];
    [toHashData appendData:signedPartData];
    [toHashData appendData:trailerData];
    
    // TODO: Investigate how to handle V3 scenario here
    // check signed hash value, should match
    if (self.version == 0x04) {
        // Calculate hash value
        let calculatedHashValueData = [[toHashData pgp_HashedWithAlgorithm:self.hashAlgoritm] subdataWithRange:(NSRange){0, 2}];
        
        if (!PGPEqualObjects(self.signedHashValueData, calculatedHashValueData)) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Verification failed. Signature hash validation failed." }];
            }
            return NO;
        }
    }
    
    switch (signingKeyPacket.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSASignOnly:
        case PGPPublicKeyAlgorithmRSAEncryptOnly: {
            // convert mpi data to binary signature_bn_bin
            let signatureMPI = [self signatureMPI:PGPMPIdentifierN];
            //let signatureMPI = self.signatureMPIs[0];
            
            // encoded m value
            let _Nullable encryptedEmData = [signatureMPI bodyData];
            // decrypted encoded m value
            let _Nullable decryptedEmData = [PGPRSA publicDecrypt:encryptedEmData withPublicKeyPacket:signingKeyPacket];
            
            // calculate EM and compare with decrypted EM. PKCS-emsa Encoded M.
            let keySize = ([signingKeyPacket publicMPI:PGPMPIdentifierN].bigNum.bitsCount + 7) / 8; // ks;
            let emData = [PGPPKCSEmsa encode:self.hashAlgoritm message:toHashData encodedMessageLength:keySize error:error];
            if (!PGPEqualObjects(emData, decryptedEmData)) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"em hash dont match" }];
                }
                return NO;
            }
        } break;
        case PGPPublicKeyAlgorithmDSA:{
            return [PGPDSA verify:toHashData signature:self withPublicKeyPacket:signingKeyPacket];
        } break;
        case PGPPublicKeyAlgorithmECDSA:
        case PGPPublicKeyAlgorithmEdDSA:
            return [PGPEC verify:toHashData signature:self withPublicKeyPacket:signingKeyPacket withHashAlgorithm:self.hashAlgoritm];
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmECDH:
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
            PGPLogWarning(@"Algorithm %@ is not supported.", @(signingKeyPacket.publicKeyAlgorithm));
            return NO;
            break;
    }
    
    
    
    return YES;
    
}


#pragma mark - Sign

// 5.2.4.  Computing Signatures
// http://tools.ietf.org/html/rfc4880#section-5.2.4
// @see https://github.com/singpolyma/openpgp-spec/blob/master/key-signatures

/// Sign the signature with the given key.
/// Set signatureMPIArray and updates signed hash.
///
/// Update sign related values. This method mutate the signature.
- (BOOL)signData:(nullable NSData *)inputData withKey:(PGPKey *)key subKey:(nullable PGPKey *)subKey passphrase:(nullable NSString *)passphrase userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(key, PGPKey);

    if (!key.secretKey) {
        PGPLogDebug(@"Missing secret key.");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing secret key" }];
        }
        return NO;
    }

    PGPAssertClass(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket); // Signing key packet not found

    if (!key.signingSecretKey) {
        // As of PGP Desktop. The signing signature may be missing.
        PGPLogDebug(@"Missing signature for the secret key %@", key.secretKey.keyID);
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorMissingSignature userInfo:@{ NSLocalizedDescriptionKey: @"Missing signature for the secret key." }];
        }
        return NO;
    }

    // it this is right? set public key algorithm from secret key packet
    self.publicKeyAlgorithm = key.signingSecretKey.publicKeyAlgorithm;

    if (key.signingSecretKey.isEncryptedWithPassphrase && passphrase && passphrase.length > 0) {
        NSError *decryptError;
        // Copy secret key instance, then decrypt on copy, not on the original (do not leave unencrypted instance around)
        key = [key decryptedWithPassphrase:PGPNN(passphrase) error:&decryptError];
        //signingKeyPacket = [signingKeyPacket decryptedWithPassphrase:PGPNN(passphrase) error:&decryptError];
        
        // When error can be passed back to caller, we want to avoid assertion, since there is no way to
        // know if packet can be decrypted and it is a typical user error to provide the wrong passhrase.
        if(key.signingSecretKey == nil && error != nil) {
            *error = decryptError;
            return NO;
        }
        
        NSAssert(key.signingSecretKey && !decryptError, @"decrypt error %@", decryptError);
    }

    // signed part data
    if (self.hashedSubpackets.count == 0) {
        // add hashed subpacket - REQUIRED
        let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
        self.hashedSubpackets = @[creationTimeSubpacket];
        PGPLogDebug(@"Signature without subpackets. Adding minimal set of subpackets.");
    }

    let signedPartData = [self buildSignedPart:self.hashedSubpackets];
    // calculate trailer
    let _Nullable trailerData = [self calculateTrailerFor:signedPartData];

    // build toSignData, toSign
    let _Nullable toSignData = [self buildDataToSignForType:self.type inputData:inputData key:key subKey:subKey userID:userID error:error];
    if (!toSignData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Can't sign" }];
        }
        return NO;
    }
    // toHash = toSignData + signedPartData + trailerData;
    let toHashData = [NSMutableData dataWithData:toSignData];
    [toHashData appendData:signedPartData];
    [toHashData appendData:trailerData];

    // == Computing Signatures ==
    // Encrypt hash data Packet signature MPIArray
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // Encrypted m value (PKCS emsa encrypted)
            let keySize = ([key.signingSecretKey publicMPI:PGPMPIdentifierN].bigNum.bitsCount + 7) / 8; // ks;
            let em = [PGPPKCSEmsa encode:self.hashAlgoritm message:toHashData encodedMessageLength:keySize error:nil];
            let encryptedEmData = [PGPRSA privateEncrypt:em withSecretKeyPacket:key.signingSecretKey];
            if (!encryptedEmData) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Sign Encryption failed" }];
                }
                return NO;
            }

            // store signature data as MPI
            self.signatureMPIs = @[[[PGPMPI alloc] initWithData:encryptedEmData identifier:PGPMPIdentifierM]];
        } break;
        case PGPPublicKeyAlgorithmDSA: {
            let mpis = [PGPDSA sign:toHashData key:key];
            if (mpis.count == 0) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Sign Encryption failed" }];
                }
                return NO;
            }
            self.signatureMPIs = mpis;
        } break;
        case PGPPublicKeyAlgorithmEdDSA: {
            if (self.hashAlgoritm < PGPHashSHA256) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Hash algorithm too weak: sha256 or stronger is required for EdDSA." }];
                }
                return NO;
            }
            let mpis = [PGPEC sign:toHashData key:key withHashAlgorithm:self.hashAlgoritm];
            if (mpis.count == 0) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Sign Encryption failed" }];
                }
                return NO;
            }
            self.signatureMPIs = mpis;
        } break;
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmECDSA:
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
            PGPLogWarning(@"Algorithm %@ is not supported.", @(self.publicKeyAlgorithm));
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Algorithm not supported" }];
            }
            return NO;
        break;
    }

    if (self.unhashedSubpackets.count == 0) {
        // add unhashed PGPSignatureSubpacketTypeIssuer subpacket - REQUIRED
        let keyid = [[PGPKeyID alloc] initWithFingerprint:key.signingSecretKey.fingerprint];
        PGPSignatureSubpacket *issuerSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:keyid];
        self.unhashedSubpackets = @[issuerSubpacket];
        PGPLogDebug(@"Signature without subpackets. Adding minimal set of subpackets.");
    }

    // Checksum
    // Two-octet field holding the left 16 bits of the signed hash value.
    // Calculate hash value
    let hashValueData = [[self calculateSignedHashForDataToSign:toSignData] subdataWithRange:(NSRange){0, 2}];
    self.signedHashValueData = hashValueData;
    return YES;
}

- (nullable NSData *)buildDataToVerifyForType:(PGPSignatureType)type key:(nullable PGPKey *)key userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error {
    let toSignData = [NSMutableData data];
    switch (type) {
        
        case PGPSignatureGenericCertificationUserIDandPublicKey: // 0x10
        case PGPSignaturePersonalCertificationUserIDandPublicKey: // 0x11
        case PGPSignatureCasualCertificationUserIDandPublicKey: // 0x12
        case PGPSignaturePositiveCertificationUserIDandPublicKey: // 0x13
        case PGPSignatureCertificationRevocation: // 0x28
        {
            if (!key.publicKey) {
                if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing key packet." }]; }
                return nil;
            }
            // A certification signature (type 0x10 through 0x13)
            
            // When a signature is made over a key, the hash data starts with the
            // octet 0x99, followed by a two-octet length of the key, and then body
            // of the key packet. (Note that this is an old-style packet header for
            // a key packet with two-octet length.)
            
            PGPPublicKeyPacket *publicKey = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);
            let signingKeyData = [publicKey exportKeyPacketOldStyle];
            [toSignData appendData:signingKeyData];
            
            if (key.publicKey) {
                let secretPartialKey = key.publicKey;
                NSAssert(secretPartialKey.users.count > 0, @"Need at least one user for the key.");
                
                BOOL userIsValid = NO;
                for (PGPUser *user in secretPartialKey.users) {
                    if (PGPEqualObjects(user.userID, userID)) {
                        userIsValid = YES;
                        break;
                    }
                }
                
                if (!userIsValid) {
                    PGPLogDebug(@"Invalid user id");
                    if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Invalid user id" }]; }
                    return nil;
                }
            }
            
            if (userID.length > 0) {
                let _Nullable userIDData = [userID dataUsingEncoding:NSUTF8StringEncoding];
                if (!userIDData) {
                    if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Invalid user id" }]; }
                    return nil;
                }
                
                if (self.version == 0x04) {
                    // constant tag (1)
                    UInt8 userIDConstant = 0xB4;
                    [toSignData appendBytes:&userIDConstant length:1];
                    
                    // length (4)
                    UInt32 userIDLength = (UInt32)userIDData.length;
                    userIDLength = CFSwapInt32HostToBig(userIDLength);
                    [toSignData appendBytes:&userIDLength length:4];
                }
                // data
                [toSignData pgp_appendData:userIDData];
            }
            // TODO user attributes alternative
            // https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.4
            // UInt8 userAttributeConstant = 0xD1;
            //[data appendBytes:&userAttributeConstant length:sizeof(userAttributeConstant)];
            
        } break;
        default:
            
            break;
    }
    return toSignData;
}


- (nullable NSData *)buildDataToSignForType:(PGPSignatureType)type inputData:(nullable NSData *)inputData key:(nullable PGPKey *)key subKey:(nullable PGPKey *)subKey userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error {
    let toSignData = [NSMutableData data];
    switch (type) {
        case PGPSignatureBinaryDocument:
        case PGPSignatureCanonicalTextDocument: {
            if (!inputData) {
                if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Missing input data" }]; }
                return nil;
            }
            [toSignData pgp_appendData:inputData];
        } break;
        case PGPSignatureSubkeyBinding: { // 0x18
            // the subkey using the same format as the main key (also using 0x99 as the first octet).
            if (!key.signingSecretKey || !subKey) {
                if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing valid key packet." }]; }
                return nil;
            }

            let signingKeyData = [key.signingSecretKey exportKeyPacketOldStyle];
            [toSignData appendData:signingKeyData];

            let _Nullable signingSubKeyData = [PGPCast(subKey.publicKey.primaryKeyPacket, PGPPublicKeyPacket) exportKeyPacketOldStyle];
            PGPAssertClass(signingSubKeyData, NSData);
            [toSignData pgp_appendData:signingSubKeyData];
        } break;
        case PGPSignaturePrimaryKeyBinding: { // 0x19
            // A primary key binding signature (type 0x19) then hashes
            if (!key.signingSecretKey) {
                if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing key packet." }]; }
                return nil;
            }

            let signingKeyData = [key.signingSecretKey exportKeyPacketOldStyle];
            [toSignData appendData:signingKeyData];
        } break;
        case PGPSignatureGenericCertificationUserIDandPublicKey: // 0x10
        case PGPSignaturePersonalCertificationUserIDandPublicKey: // 0x11
        case PGPSignatureCasualCertificationUserIDandPublicKey: // 0x12
        case PGPSignaturePositiveCertificationUserIDandPublicKey: // 0x13
        case PGPSignatureCertificationRevocation: // 0x28
        {
            if (!key.signingSecretKey) {
                if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing key packet." }]; }
                return nil;
            }
            // A certification signature (type 0x10 through 0x13)

            // When a signature is made over a key, the hash data starts with the
            // octet 0x99, followed by a two-octet length of the key, and then body
            // of the key packet. (Note that this is an old-style packet header for
            // a key packet with two-octet length.)

            let signingKeyData = [key.signingSecretKey exportKeyPacketOldStyle];
            [toSignData appendData:signingKeyData];

            if (key.secretKey) {
                let secretPartialKey = key.secretKey;
                NSAssert(secretPartialKey.users.count > 0, @"Need at least one user for the key.");

                BOOL userIsValid = NO;
                for (PGPUser *user in secretPartialKey.users) {
                    if (PGPEqualObjects(user.userID, userID)) {
                        userIsValid = YES;
                    }
                }

                if (!userIsValid) {
                    PGPLogDebug(@"Invalid user id");
                    if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Invalid user id" }]; }
                    return nil;
                }
            }

            if (userID.length > 0) {
                let _Nullable userIDData = [userID dataUsingEncoding:NSUTF8StringEncoding];
                if (!userIDData) {
                    if (error) { *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Invalid user id" }]; }
                    return nil;
                }

                if (self.version == 0x04) {
                    // constant tag (1)
                    UInt8 userIDConstant = 0xB4;
                    [toSignData appendBytes:&userIDConstant length:1];

                    // length (4)
                    UInt32 userIDLength = (UInt32)userIDData.length;
                    userIDLength = CFSwapInt32HostToBig(userIDLength);
                    [toSignData appendBytes:&userIDLength length:4];
                }
                // data
                [toSignData pgp_appendData:userIDData];
            }
            // TODO user attributes alternative
            // UInt8 userAttributeConstant = 0xD1;
            //[data appendBytes:&userAttributeConstant length:sizeof(userAttributeConstant)];

        } break;
        default:
            [toSignData pgp_appendData:inputData];
            break;
    }
    return toSignData;
}

- (nullable NSData *)calculateTrailerFor:(NSData *)signedPartData {
    if (self.version != 0x04) {
        PGPLogError(@"Unsupported signature version: %@, expected version 4", @(self.version));
        return nil;
    }

    let trailerData = [NSMutableData data];
    UInt8 prefix[2] = {self.version, 0xFF};
    [trailerData appendBytes:&prefix length:2];

    UInt32 signatureLength = (UInt32)signedPartData.length; // + 6; // ??? (note that this number does not include these final six octets)
    signatureLength = CFSwapInt32HostToBig(signatureLength);
    [trailerData appendBytes:&signatureLength length:4];

    return trailerData;
}

#pragma mark - Parse

/**
 *  5.2.  Signature Packet (Tag 2)
 *
 *  @param packetBody Packet body
 */

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    __unused NSUInteger position = [super parsePacketBody:packetBody error:error];
    NSUInteger startPosition = position;

    UInt8 parsedVersion = 0;
    // One-octet version number.
    [packetBody getBytes:&parsedVersion range:(NSRange){position, 1}];
    position = position + 1;

    switch (parsedVersion) {
        case 0x04:
            position = [self parseV4PacketBody:packetBody error:error];
            break;
        case 0x03:
            position = [self parseV3PacketBody:packetBody error:error];
            break;
        default:
            NSAssert(true, @"Unsupported signature packet version");
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Signature version %@ is supported at the moment", @(parsedVersion)] }];
            }
            return startPosition + packetBody.length;
            break;
    }
    return position;
}

// FIXME: V3 signatures fail somewehere (I don't know where yet) because everything is designed
// for V4 and uses V4 specific data to (for example) validate signature
- (NSUInteger)parseV3PacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(packetBody, NSData);
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // V3
    // One-octet version number (3).
    UInt8 parsedVersion = 0;
    [packetBody getBytes:&parsedVersion range:(NSRange){position, 1}];
    position = position + 1;

    if (parsedVersion != 0x03) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unexpected packed version. Expected version 3" }];
        }
        return position;
    }

    // One-octet length of following hashed material.  MUST be 5.
    UInt8 parsedLength = 0;
    [packetBody getBytes:&parsedLength range:(NSRange){position, 1}];
    position = position + 1;
    NSAssert(parsedLength == 5, @"Invalid signature data");

    // One-octet signature type.
    [packetBody getBytes:&_type range:(NSRange){position, 1}];
    position = position + 1;

    // Four-octet creation time
    UInt32 parsedCreationTimestamp = 0;
    [packetBody getBytes:&parsedCreationTimestamp range:(NSRange){position, 4}];
    parsedCreationTimestamp = CFSwapInt32BigToHost(parsedCreationTimestamp);
    position = position + 4;

    // Eight-octet Key ID of signer
    PGPKeyID *parsedkeyID = [[PGPKeyID alloc] initWithLongKey:[packetBody subdataWithRange:(NSRange){position, 8}]];
    position = position + 8;

    // One-octet public-key algorithm.
    [packetBody getBytes:&_publicKeyAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // One-octet hash algorithm.
    [packetBody getBytes:&_hashAlgoritm range:(NSRange){position, 1}];
    position = position + 1;

    // Two-octet field holding the left 16 bits of the signed hash value.
    self.signedHashValueData = [packetBody subdataWithRange:(NSRange){position, 2}];
    position = position + 2;

    // 5.2.2. One or more multiprecision integers comprising the signature. This portion is algorithm specific
    // Signature
    switch (_publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // multiprecision integer (MPI) of RSA signature value m**d mod n.
            // MPI of RSA public modulus n;
            let mpiN = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierN atPosition:position];
            position = position + mpiN.packetLength;

            self.signatureMPIs = @[mpiN];
        } break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            let mpiR = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierR atPosition:position];
            position = position + mpiR.packetLength;

            // MPI of DSA value s.
            let mpiS = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierS atPosition:position];
            position = position + mpiS.packetLength;

            self.signatureMPIs = @[mpiR, mpiS];
        } break;
        case PGPPublicKeyAlgorithmEdDSA: {
            NSAssert(NO, @"A version 3 signature MUST NOT be created and MUST NOT be used with EdDSA");
        } break;
        case PGPPublicKeyAlgorithmElgamalEncryptorSign: {
            // MPI of Elgamal (Diffie-Hellman) value g**k mod p.
            let mpiR = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierR atPosition:position];
            position = position + mpiR.packetLength;

            // MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
            let mpiS = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierS atPosition:position];
            position = position + mpiS.packetLength;

            self.signatureMPIs = @[mpiR, mpiS];
        } break;
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmElgamal: // encrypt only. ignore.
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
            break;
    }

    // convert V3 values to V4 subpackets
    let keyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:parsedkeyID];
    self.unhashedSubpackets = [self.unhashedSubpackets arrayByAddingObject:keyIDSubpacket];

    let creationDateTime = [NSDate dateWithTimeIntervalSince1970:parsedCreationTimestamp];
    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:creationDateTime];
    self.hashedSubpackets = [self.hashedSubpackets arrayByAddingObject:creationTimeSubpacket];

    return position;
}

- (NSUInteger)parseV4PacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(packetBody, NSData);

    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // A V4 signature hashes the packet body
    // starting from its first field, the version number, through the end
    // of the hashed subpacket data.  Thus, the fields hashed are the
    // signature version, the signature type, the public-key algorithm, the
    // hash algorithm, the hashed subpacket length, and the hashed
    // subpacket body.

    UInt8 parsedVersion = 0;
    // V4
    // One-octet version number (4).
    [packetBody getBytes:&parsedVersion range:(NSRange){position, 1}];
    position = position + 1;

    if (parsedVersion != 0x04) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unexpected packed version. Expected version 4" }];
        }
        return position;
    }

    // One-octet signature type.
    [packetBody getBytes:&_type range:(NSRange){position, 1}];
    position = position + 1;

    // One-octet public-key algorithm.
    [packetBody getBytes:&_publicKeyAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // One-octet hash algorithm.
    [packetBody getBytes:&_hashAlgoritm range:(NSRange){position, 1}];
    position = position + 1;

    // Two-octet scalar octet count for following hashed subpacket data.
    UInt16 hashedOctetCount = 0;
    [packetBody getBytes:&hashedOctetCount range:(NSRange){position, 2}];
    hashedOctetCount = CFSwapInt16BigToHost(hashedOctetCount);
    position = position + 2;

    // Hashed subpacket data set (zero or more subpackets)
    NSData *hashedSubpacketsData = nil;
    if (hashedOctetCount > 0) {
        hashedSubpacketsData = [packetBody subdataWithRange:(NSRange){position, hashedOctetCount}];
        position = position + hashedOctetCount;

        NSMutableArray *hashedSubpackets = [NSMutableArray arrayWithCapacity:hashedOctetCount];

        NSUInteger positionSubpacket = 0;
        while (positionSubpacket < hashedSubpacketsData.length) {
            let _Nullable subpacket = [PGPSignaturePacket getSubpacketStartingAtPosition:positionSubpacket fromData:hashedSubpacketsData];
            if (subpacket) {
                [hashedSubpackets pgp_addObject:subpacket];
                positionSubpacket = positionSubpacket + subpacket.length;
            } else {
                positionSubpacket += 2; // move two bytes to next subpacket (header length)
            }
        }

        self.hashedSubpackets = hashedSubpackets;
    }

    // Two-octet scalar octet count for the following unhashed subpacket
    UInt16 unhashedOctetCount = 0;
    [packetBody getBytes:&unhashedOctetCount range:(NSRange){position, 2}];
    unhashedOctetCount = CFSwapInt16BigToHost(unhashedOctetCount);
    position = position + 2;

    // Unhashed subpacket data set (zero or more subpackets)
    NSData *unhashedSubpacketsData = nil;
    if (unhashedOctetCount > 0) {
        unhashedSubpacketsData = [packetBody subdataWithRange:(NSRange){position, unhashedOctetCount}];
        position = position + unhashedOctetCount;

        NSMutableArray *unhashedSubpackets = [NSMutableArray arrayWithCapacity:unhashedOctetCount];

        // Loop subpackets
        NSUInteger positionSubpacket = 0;
        while (positionSubpacket < unhashedSubpacketsData.length) {
            let _Nullable subpacket = [PGPSignaturePacket getSubpacketStartingAtPosition:positionSubpacket fromData:unhashedSubpacketsData];
            if (subpacket) {
                [unhashedSubpackets pgp_addObject:subpacket];
                positionSubpacket = positionSubpacket + subpacket.length;
            } else {
                positionSubpacket += 2; // move two bytes to next subpacket (header length)
            }
        }

        self.unhashedSubpackets = unhashedSubpackets;
    }

    // Two-octet field holding the left 16 bits of the signed hash value.
    self.signedHashValueData = [packetBody subdataWithRange:(NSRange){position, 2}];

    position = position + 2;

    // 5.2.2. One or more multiprecision integers comprising the signature. This portion is algorithm specific
    // Signature
    switch (_publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            // multiprecision integer (MPI) of RSA signature value m**d mod n.
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierN atPosition:position];
            position = position + mpiN.packetLength;

            self.signatureMPIs = @[mpiN];
        } break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA: {
            // MPI of DSA value r.
            PGPMPI *mpiR = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierR atPosition:position];
            position = position + mpiR.packetLength;

            // MPI of DSA value s.
            PGPMPI *mpiS = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierS atPosition:position];
            position = position + mpiS.packetLength;

            self.signatureMPIs = @[mpiR, mpiS];
        } break;
        case PGPPublicKeyAlgorithmEdDSA: {
            // MPI of an EC point r.
            let mpiR = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierR atPosition:position];
            position = position + mpiR.packetLength;

            // EdDSA value s, in MPI, in the little endian representation
            let mpiS = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierS atPosition:position];
            position = position + mpiS.packetLength;

            self.signatureMPIs = @[mpiR, mpiS];
        } break;
        case PGPPublicKeyAlgorithmElgamalEncryptorSign: {
            // MPI of Elgamal (Diffie-Hellman) value g**k mod p.
            PGPMPI *mpiR = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierR atPosition:position];
            position = position + mpiR.packetLength;

            // MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
            PGPMPI *mpiS = [[PGPMPI alloc] initWithMPIData:packetBody identifier:PGPMPIdentifierS atPosition:position];
            position = position + mpiS.packetLength;

            self.signatureMPIs = @[mpiR, mpiS];
        } break;
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmElgamal: // encrypt only. ignore.
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
            break;
    }

    return position;
}

#pragma mark - Private

// I don't like this part, really ugly
// This is because subpacket length is unknow and header need to be found first
// then subpacket can be parsed
+ (nullable PGPSignatureSubpacket *)getSubpacketStartingAtPosition:(NSUInteger)subpacketsPosition fromData:(NSData *)subpacketsData {
    let headerRange = (NSRange){subpacketsPosition, MIN((NSUInteger)6, subpacketsData.length - subpacketsPosition)}; // up to 5+1 octets
    let guessHeaderData = [subpacketsData subdataWithRange:headerRange]; // this is "may be" header to be parsed
    let subpacketHeader = [PGPSignatureSubpacket subpacketHeaderFromData:guessHeaderData];

    if (subpacketHeader.bodyLength == 0) {
        // missing body, ignore.
        return nil;
    }

    let subPacketBodyRange = (NSRange){subpacketsPosition + subpacketHeader.headerLength, subpacketHeader.bodyLength};
    let subPacketBody = [subpacketsData subdataWithRange:subPacketBodyRange];
    let subpacket = [[PGPSignatureSubpacket alloc] initWithHeader:subpacketHeader body:subPacketBody];

    return subpacket;
}

/// count + subpackets(count)
+ (NSData *)buildSubpacketsCollectionData:(NSArray <PGPSignatureSubpacket *> *)subpacketsCollection {
    let data = [NSMutableData data];
    if (subpacketsCollection.count == 0) {
        // 0x00 0x00
        UInt16 zeroZero = 0;
        [data appendBytes:&zeroZero length:2];
        return data;
    }

    let subpackets = [NSMutableData data];
    // Hashed subpacket data set (zero or more subpackets)
    for (PGPSignatureSubpacket *subpacket in subpacketsCollection) {
        NSError *error = nil;
        let subpacketData = [subpacket export:&error];
        [subpackets pgp_appendData:subpacketData];
    }
    // Two-octet scalar octet count for following hashed subpacket data.
    UInt16 countBE = CFSwapInt16HostToBig((UInt16)subpackets.length);
    [data appendBytes:&countBE length:2];
    // subackets data
    [data appendData:subpackets];
    return data;
}

@end

NS_ASSUME_NONNULL_END
