//
//  PGPKeyGenerator.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 25/08/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKeyGenerator.h"
#import "PGPTypes.h"
#import "PGPPartialSubKey+Private.h"
#import "PGPPublicKeyPacket+Private.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPMacros+Private.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPCryptoHash.h"
#import "PGPCryptoUtils.h"
#import "PGPRSA.h"
#import "PGPDSA.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPKeyGenerator ()

@end

@implementation PGPKeyGenerator

- (instancetype)init {
    if ((self = [super init])) {
        _keyAlgorithm = PGPPublicKeyAlgorithmRSA;
        _keyBitsLength = 2048;
        _createDate = NSDate.date;
        _version = 0x04;
        _cipherAlgorithm = PGPSymmetricAES256;
        _hashAlgorithm = PGPHashSHA256;
    }
    return self;
}

- (nullable PGPKeyMaterial *)fillMPIForPublic:(PGPPublicKeyPacket *)publicKeyPacket andSecret:(PGPSecretKeyPacket *)secretKeyPacket withKeyAlgorithm:(PGPPublicKeyAlgorithm)algorithm bits:(int)bits {
    PGPKeyMaterial *keyMaterial = nil;

    switch (algorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            keyMaterial = [PGPRSA generateNewKeyMPIArray:bits];
            publicKeyPacket.publicMPIArray = @[keyMaterial.n, keyMaterial.e];
            secretKeyPacket.secretMPIArray = @[keyMaterial.d, keyMaterial.p, keyMaterial.q, keyMaterial.u];
        } break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA: {
            keyMaterial = [PGPDSA generateNewKeyMPIArray:bits];
            publicKeyPacket.publicMPIArray = @[keyMaterial.p, keyMaterial.q, keyMaterial.g, keyMaterial.y];
            secretKeyPacket.secretMPIArray = @[keyMaterial.x];
        } break;
        default:
            NSAssert(NO, @"Not supported");
            return nil;
    }

    secretKeyPacket.publicMPIArray = publicKeyPacket.publicMPIArray;
    return keyMaterial;
}

- (nullable PGPKey *)buildKeyWithPassphrase:(nullable NSString *)passphrase {
    // Public key
    let publicKeyPacket = [[PGPPublicKeyPacket alloc] init];
    publicKeyPacket.version = self.version;
    publicKeyPacket.publicKeyAlgorithm = self.keyAlgorithm;
    publicKeyPacket.createDate = self.createDate;

    // Secret Key
    let secretKeyPacket = [[PGPSecretKeyPacket alloc] init];
    secretKeyPacket.version = self.version;
    secretKeyPacket.publicKeyAlgorithm = publicKeyPacket.publicKeyAlgorithm;
    secretKeyPacket.symmetricAlgorithm = self.cipherAlgorithm;
    secretKeyPacket.createDate = publicKeyPacket.createDate;

    // Fill MPIs
    [self fillMPIForPublic:publicKeyPacket andSecret:secretKeyPacket withKeyAlgorithm:self.keyAlgorithm bits:self.keyBitsLength];

    // Encrypt with passphrase
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:secretKeyPacket.symmetricAlgorithm];
    if (!passphrase) {
        secretKeyPacket.s2kUsage = PGPS2KUsageNonEncrypted;
        secretKeyPacket.s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSimple hashAlgorithm:self.hashAlgorithm];
        secretKeyPacket.ivData = [NSMutableData dataWithLength:blockSize];
    } else {
        secretKeyPacket.ivData = [PGPCryptoUtils randomData:blockSize];
        secretKeyPacket.s2kUsage = PGPS2KUsageEncryptedAndHashed;

        let s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierIteratedAndSalted hashAlgorithm:self.hashAlgorithm];
        secretKeyPacket.s2k = s2k;

        // build encryptedMPIPartData
        let plaintextMPIPartData = [NSMutableData data];

        for (PGPMPI *mpi in secretKeyPacket.secretMPIArray) {
            [plaintextMPIPartData pgp_appendData:[mpi exportMPI]];
        }

        switch (secretKeyPacket.s2kUsage) {
            case PGPS2KUsageEncryptedAndHashed: {
                // a 20-octet SHA-1 hash of the plaintext of the algorithm-specific portion
                let hashData = plaintextMPIPartData.pgp_SHA1;
                [plaintextMPIPartData pgp_appendData:hashData];
            } break;
            case PGPS2KUsageEncrypted: {
                // a two-octet checksum of the plaintext of the algorithm-specific portion
                UInt16 checksum = CFSwapInt16HostToBig(plaintextMPIPartData.pgp_Checksum);
                [plaintextMPIPartData appendBytes:&checksum length:2];
            } break;
            default:
                break;
        }

        let sessionKeyData = [s2k produceSessionKeyWithPassphrase:passphrase symmetricAlgorithm:self.cipherAlgorithm];
        if (sessionKeyData) {
            secretKeyPacket.encryptedMPIPartData = [PGPCryptoCFB encryptData:plaintextMPIPartData sessionKeyData:sessionKeyData symmetricAlgorithm:self.cipherAlgorithm iv:secretKeyPacket.ivData];
        }
    }

    // Create Key
    let partialPublicKey = [[PGPPartialKey alloc] initWithPackets:@[publicKeyPacket]];
    let partialSecretKey = [[PGPPartialKey alloc] initWithPackets:@[secretKeyPacket]];
    return [[PGPKey alloc] initWithSecretKey:partialSecretKey publicKey:partialPublicKey];
}

- (PGPKey *)addSubKeyTo:(PGPKey *)parentKey {
    let publicSubKeyPacket = [[PGPPublicSubKeyPacket alloc] init];
    publicSubKeyPacket.version = self.version;
    publicSubKeyPacket.publicKeyAlgorithm = self.keyAlgorithm;
    publicSubKeyPacket.createDate = self.createDate;

    // Secret Key
    let secretSubKeyPacket = [[PGPSecretSubKeyPacket alloc] init];
    secretSubKeyPacket.version = self.version;
    secretSubKeyPacket.publicKeyAlgorithm = publicSubKeyPacket.publicKeyAlgorithm;
    secretSubKeyPacket.s2kUsage = PGPS2KUsageNonEncrypted;
    secretSubKeyPacket.s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSimple hashAlgorithm:self.hashAlgorithm];
    secretSubKeyPacket.symmetricAlgorithm = self.cipherAlgorithm;
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:secretSubKeyPacket.symmetricAlgorithm];
    secretSubKeyPacket.ivData = [NSMutableData dataWithLength:blockSize];
    secretSubKeyPacket.createDate = publicSubKeyPacket.createDate;

    [self fillMPIForPublic:publicSubKeyPacket andSecret:secretSubKeyPacket withKeyAlgorithm:self.keyAlgorithm bits:self.keyBitsLength];

    // Create Key
    let publicSubKey = [[PGPPartialSubKey alloc] initWithPacket:publicSubKeyPacket];
    let secretSubKey = [[PGPPartialSubKey alloc] initWithPacket:secretSubKeyPacket];

    parentKey.publicKey.subKeys = [parentKey.publicKey.subKeys arrayByAddingObject:publicSubKey];
    parentKey.secretKey.subKeys = [parentKey.secretKey.subKeys arrayByAddingObject:secretSubKey];

    return [[PGPKey alloc] initWithSecretKey:secretSubKey publicKey:publicSubKey];
}

- (NSArray<PGPSignatureSubpacket *> *)signatureCommonHashedSubpackets {
    return @[
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:self.createDate],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowSignData), @(PGPSignatureFlagAllowCertifyOtherKeys)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredHashAlgorithm andValue:@[@(PGPHashSHA256), @(PGPHashSHA384), @(PGPHashSHA512)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm andValue:@[@(PGPSymmetricAES256), @(PGPSymmetricAES192), @(PGPSymmetricAES128), @(PGPSymmetricCAST5), @(PGPSymmetricTripleDES), @(PGPSymmetricIDEA)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredCompressionAlgorithm andValue:@[@(PGPCompressionBZIP2), @(PGPCompressionZLIB), @(PGPCompressionZIP)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeFeatures andValue:@[@(PGPFeatureModificationDetection)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyServerPreference andValue:@[@(PGPKeyServerPreferenceNoModify)]]
     ];
}

- (nullable PGPSignaturePacket *)buildPublicSignaturePacketFor:(PGPKey *)key {
    let publicKeyPacket = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);

    let publicKeySignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignaturePositiveCertificationUserIDandPublicKey hashAlgorithm:self.hashAlgorithm];
    publicKeySignaturePacket.version = publicKeyPacket.version;
    publicKeySignaturePacket.publicKeyAlgorithm = publicKeyPacket.publicKeyAlgorithm;

    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:publicKeyPacket.keyID];

    publicKeySignaturePacket.hashedSubpackets = [self.signatureCommonHashedSubpackets arrayByAddingObject:[[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePrimaryUserID andValue:@(YES)]];
    publicKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    NSError *error;
    let userID = key.publicKey.users.firstObject.userID;
    if (![publicKeySignaturePacket signData:nil withKey:key subKey:nil passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return publicKeySignaturePacket;
}

- (nullable PGPSignaturePacket *)buildSecretSignaturePacketFor:(PGPKey *)key {
    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);

    let secretKeySignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignaturePositiveCertificationUserIDandPublicKey hashAlgorithm:self.hashAlgorithm];
    secretKeySignaturePacket.version = secretKeyPacket.version;
    secretKeySignaturePacket.publicKeyAlgorithm = secretKeyPacket.publicKeyAlgorithm;

    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:secretKeyPacket.keyID];

    secretKeySignaturePacket.hashedSubpackets = self.signatureCommonHashedSubpackets;
    secretKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    NSError *error;
    let userID = key.secretKey.users.firstObject.userID;
    if (![secretKeySignaturePacket signData:nil withKey:key subKey:nil passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return secretKeySignaturePacket;
}


- (nullable PGPSignaturePacket *)buildPublicSignaturePacketForSubKey:(PGPKey *)subKey parentKey:(PGPKey *)parentKey {
    let publicSubKeyPacket = PGPCast(subKey.publicKey.primaryKeyPacket, PGPPublicSubKeyPacket);

    let publicSubKeySignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureSubkeyBinding hashAlgorithm:self.hashAlgorithm];
    publicSubKeySignaturePacket.version = publicSubKeyPacket.version;
    publicSubKeySignaturePacket.publicKeyAlgorithm = publicSubKeyPacket.publicKeyAlgorithm;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowEncryptCommunications), @(PGPSignatureFlagAllowEncryptStorage)]];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:parentKey.signingSecretKey.keyID];

    publicSubKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket, keyFlagsSubpacket];
    publicSubKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    NSError *error;
    let userID = parentKey.publicKey.users.firstObject.userID;
    if (![publicSubKeySignaturePacket signData:nil withKey:parentKey subKey:subKey passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return publicSubKeySignaturePacket;
}

- (nullable PGPSignaturePacket *)buildSecretSignaturePacketForSubKey:(PGPKey *)subKey parentKey:(PGPKey *)parentKey {
    let secretSubKeyPacket = PGPCast(subKey.secretKey.primaryKeyPacket, PGPSecretSubKeyPacket);

    let secretSubKeySignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureSubkeyBinding hashAlgorithm:self.hashAlgorithm];
    secretSubKeySignaturePacket.version = secretSubKeyPacket.version;
    secretSubKeySignaturePacket.publicKeyAlgorithm = secretSubKeyPacket.publicKeyAlgorithm;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowEncryptCommunications), @(PGPSignatureFlagAllowEncryptStorage)]];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:parentKey.signingSecretKey.keyID];

    secretSubKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket, keyFlagsSubpacket];
    secretSubKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    NSError *error;
    let userID = parentKey.secretKey.users.firstObject.userID;
    if (![secretSubKeySignaturePacket signData:nil withKey:parentKey subKey:subKey passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return secretSubKeySignaturePacket;
}

- (PGPKey *)generateFor:(NSString *)userID passphrase:(nullable NSString *)passphrase {
    let key = [self buildKeyWithPassphrase:passphrase];
    let subKey = [self addSubKeyTo:key];

    let userPublic = [[PGPUser alloc] initWithUserIDPacket:[[PGPUserIDPacket alloc] initWithUserID:userID]];
    let userSecret = [[PGPUser alloc] initWithUserIDPacket:[[PGPUserIDPacket alloc] initWithUserID:userID]];
    key.publicKey.users = @[userPublic];
    key.secretKey.users = @[userSecret];

    // Public

    let publicKeySignaturePacket = [self buildPublicSignaturePacketFor:key];
    userPublic.selfCertifications = [userPublic.selfCertifications arrayByAddingObject:publicKeySignaturePacket];

    let publicSubKeySignaturePacket = [self buildPublicSignaturePacketForSubKey:subKey parentKey:key];
    key.publicKey.subKeys.firstObject.bindingSignature = publicSubKeySignaturePacket;

    // Secret

    let secretKeySignaturePacket = [self buildSecretSignaturePacketFor:key];
    userSecret.selfCertifications = [userSecret.selfCertifications arrayByAddingObject:secretKeySignaturePacket];

    let secretSubKeySignaturePacket = [self buildSecretSignaturePacketForSubKey:subKey parentKey:key];
    key.secretKey.subKeys.firstObject.bindingSignature = secretSubKeySignaturePacket;

    return key;
}

@end

NS_ASSUME_NONNULL_END
