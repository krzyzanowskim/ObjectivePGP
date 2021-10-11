//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPKeyGenerator.h"
#import "PGPTypes.h"
#import "PGPPartialSubKey+Private.h"
#import "PGPPartialKey+Private.h"
#import "PGPPublicKeyPacket+Private.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPPublicSubKeyPacket.h"
#import "PGPSecretSubKeyPacket.h"
#import "PGPSignatureSubpacketEmbeddedSignature.h"
#import "PGPUser+Private.h"
#import "PGPLogging.h"
#import "PGPUserIDPacket.h"
#import "PGPCryptoHash.h"
#import "PGPCryptoUtils.h"
#import "PGPFoundation.h"
#import "PGPRSA.h"
#import "PGPDSA.h"
#import "PGPCryptoCFB.h"
#import "PGPMacros+Private.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPKeyGenerator ()

@end

@implementation PGPKeyGenerator

- (instancetype)init {
    if ((self = [super init])) {
        _keyAlgorithm = PGPPublicKeyAlgorithmRSA;
        _keyBitsLength = 3072;
        _createDate = NSDate.date;
        _version = 0x04;
        _cipherAlgorithm = PGPSymmetricAES256;
        _hashAlgorithm = PGPHashSHA256;
    }
    return self;
}

- (nullable PGPKeyMaterial *)fillMPIForPublic:(PGPPublicKeyPacket *)publicKeyPacket andSecret:(PGPSecretKeyPacket *)secretKeyPacket withKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm bits:(int)bits {
    PGPKeyMaterial *keyMaterial = nil;

    switch (publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            keyMaterial = [PGPRSA generateNewKeyMPIArray:bits];
            publicKeyPacket.publicMPIs = @[keyMaterial.n, keyMaterial.e];
            secretKeyPacket.secretMPIs = @[keyMaterial.d, keyMaterial.p, keyMaterial.q, keyMaterial.u];
        } break;
        case PGPPublicKeyAlgorithmDSA:{
            keyMaterial = [PGPDSA generateNewKeyMPIArray:bits];
            publicKeyPacket.publicMPIs = @[keyMaterial.p, keyMaterial.q, keyMaterial.g, keyMaterial.y];
            secretKeyPacket.secretMPIs = @[keyMaterial.x];
        } break;
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmECDSA:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        case PGPPublicKeyAlgorithmDiffieHellman:
        case PGPPublicKeyAlgorithmEdDSA:
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
            PGPLogWarning(@"Not supported");
            break;
    }

    secretKeyPacket.publicMPIs = publicKeyPacket.publicMPIs;
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

        for (PGPMPI *mpi in secretKeyPacket.secretMPIs) {
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

        let sessionKeyData = [s2k produceSessionKeyWithPassphrase:PGPNN(passphrase) symmetricAlgorithm:self.cipherAlgorithm];
        if (sessionKeyData) {
            secretKeyPacket.encryptedMPIPartData = [PGPCryptoCFB encryptData:plaintextMPIPartData sessionKeyData:sessionKeyData symmetricAlgorithm:self.cipherAlgorithm iv:secretKeyPacket.ivData syncCFB:NO];
        }
    }

    // Create Key
    let partialPublicKey = [[PGPPartialKey alloc] initWithPackets:@[publicKeyPacket]];
    let partialSecretKey = [[PGPPartialKey alloc] initWithPackets:@[secretKeyPacket]];
    return [[PGPKey alloc] initWithSecretKey:partialSecretKey publicKey:partialPublicKey];
}

- (PGPKey *)addSubKeyTo:(PGPKey *)parentKey passphrase:(nullable NSString *)passphrase {
    let publicSubKeyPacket = [[PGPPublicSubKeyPacket alloc] init];
    publicSubKeyPacket.version = self.version;
    publicSubKeyPacket.publicKeyAlgorithm = self.keyAlgorithm;
    publicSubKeyPacket.createDate = self.createDate;

    // Secret Key
    let secretSubKeyPacket = [[PGPSecretSubKeyPacket alloc] init];
    secretSubKeyPacket.version = self.version;
    secretSubKeyPacket.publicKeyAlgorithm = publicSubKeyPacket.publicKeyAlgorithm;
    secretSubKeyPacket.symmetricAlgorithm = self.cipherAlgorithm;
    secretSubKeyPacket.createDate = publicSubKeyPacket.createDate;

    // Fill MPIs
    [self fillMPIForPublic:publicSubKeyPacket andSecret:secretSubKeyPacket withKeyAlgorithm:self.keyAlgorithm bits:self.keyBitsLength];

    // TODO: refactor duplicated code
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:secretSubKeyPacket.symmetricAlgorithm];
    if (!passphrase) {
        secretSubKeyPacket.s2kUsage = PGPS2KUsageNonEncrypted;
        secretSubKeyPacket.s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSimple hashAlgorithm:self.hashAlgorithm];
        secretSubKeyPacket.ivData = [NSMutableData dataWithLength:blockSize];
    } else {
        secretSubKeyPacket.ivData = [PGPCryptoUtils randomData:blockSize];
        secretSubKeyPacket.s2kUsage = PGPS2KUsageEncryptedAndHashed;

        let s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierIteratedAndSalted hashAlgorithm:self.hashAlgorithm];
        secretSubKeyPacket.s2k = s2k;

        // build encryptedMPIPartData
        let plaintextMPIPartData = [NSMutableData data];

        for (PGPMPI *mpi in secretSubKeyPacket.secretMPIs) {
            [plaintextMPIPartData pgp_appendData:[mpi exportMPI]];
        }

        switch (secretSubKeyPacket.s2kUsage) {
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

        let sessionKeyData = [s2k produceSessionKeyWithPassphrase:PGPNN(passphrase) symmetricAlgorithm:self.cipherAlgorithm];
        if (sessionKeyData) {
            secretSubKeyPacket.encryptedMPIPartData = [PGPCryptoCFB encryptData:plaintextMPIPartData sessionKeyData:sessionKeyData symmetricAlgorithm:self.cipherAlgorithm iv:secretSubKeyPacket.ivData syncCFB:NO];
        }
    }

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
    NSError *error;

    let publicSubKeyPacket = PGPCast(subKey.publicKey.primaryKeyPacket, PGPPublicSubKeyPacket);

    let publicSubKeySignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureSubkeyBinding hashAlgorithm:self.hashAlgorithm];
    publicSubKeySignaturePacket.version = publicSubKeyPacket.version;
    publicSubKeySignaturePacket.publicKeyAlgorithm = publicSubKeyPacket.publicKeyAlgorithm;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowEncryptCommunications), @(PGPSignatureFlagAllowEncryptStorage)]];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:parentKey.signingSecretKey.keyID];

    // embeded signature
    let embeddedSignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignaturePrimaryKeyBinding hashAlgorithm:self.hashAlgorithm];
    embeddedSignaturePacket.version = 0x04;
    embeddedSignaturePacket.publicKeyAlgorithm = publicSubKeyPacket.publicKeyAlgorithm;
    [embeddedSignaturePacket signData:nil withKey:subKey subKey:nil passphrase:nil userID:nil error:&error];
    let subpacketEmbeddedSignature = [[PGPSignatureSubpacketEmbeddedSignature alloc] initWithSignature:embeddedSignaturePacket];
    let embeddedSignatureSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeEmbeddedSignature andValue:subpacketEmbeddedSignature];

    publicSubKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket, keyFlagsSubpacket, embeddedSignatureSubpacket];
    publicSubKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    let userID = parentKey.publicKey.users.firstObject.userID;
    if (![publicSubKeySignaturePacket signData:nil withKey:parentKey subKey:subKey passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return publicSubKeySignaturePacket;
}

- (nullable PGPSignaturePacket *)buildSecretSignaturePacketForSubKey:(PGPKey *)subKey parentKey:(PGPKey *)parentKey {
    NSError *error;

    let secretSubKeyPacket = PGPCast(subKey.secretKey.primaryKeyPacket, PGPSecretSubKeyPacket);

    let secretSubKeySignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureSubkeyBinding hashAlgorithm:self.hashAlgorithm];
    secretSubKeySignaturePacket.version = secretSubKeyPacket.version;
    secretSubKeySignaturePacket.publicKeyAlgorithm = secretSubKeyPacket.publicKeyAlgorithm;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowEncryptCommunications), @(PGPSignatureFlagAllowEncryptStorage)]];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:parentKey.signingSecretKey.keyID];

    // embeded signature
    let embeddedSignaturePacket = [PGPSignaturePacket signaturePacket:PGPSignaturePrimaryKeyBinding hashAlgorithm:self.hashAlgorithm];
    embeddedSignaturePacket.version = secretSubKeyPacket.version;
    embeddedSignaturePacket.publicKeyAlgorithm = secretSubKeyPacket.publicKeyAlgorithm;
    [embeddedSignaturePacket signData:nil withKey:subKey subKey:nil passphrase:nil userID:nil error:&error];
    let subpacketEmbeddedSignature = [[PGPSignatureSubpacketEmbeddedSignature alloc] initWithSignature:embeddedSignaturePacket];
    let embeddedSignatureSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeEmbeddedSignature andValue:subpacketEmbeddedSignature];

    secretSubKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket, keyFlagsSubpacket, embeddedSignatureSubpacket];
    secretSubKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    let userID = parentKey.secretKey.users.firstObject.userID;
    if (![secretSubKeySignaturePacket signData:nil withKey:parentKey subKey:subKey passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return secretSubKeySignaturePacket;
}

- (PGPKey *)generateFor:(NSString *)userID passphrase:(nullable NSString *)passphrase {
    let key = [self buildKeyWithPassphrase:passphrase];
    let subKey = [self addSubKeyTo:key passphrase:passphrase];

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
