//
//  PGPKeyGenerator.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 25/08/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKeyGenerator.h"
#import "PGPTypes.h"
#import "PGPPublicKeyPacket+Private.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPKeyGenerator ()

@property (nonatomic) int keyBitsLength;
@property (nonatomic) PGPPublicKeyAlgorithm keyAlgorithm;
@property (nonatomic) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) NSString *userID;
@property (nonatomic) UInt8 version;
@property (nonatomic) NSDate *createDate;

@end

@implementation PGPKeyGenerator

- (instancetype)init {
    if ((self = [super init])) {
        _keyAlgorithm = PGPPublicKeyAlgorithmRSA;
        _keyBitsLength = 2048;
        _createDate = NSDate.date;
        _version = 0x04;
        _symmetricAlgorithm = PGPSymmetricAES256;
        _hashAlgorithm = PGPHashSHA1;
    }
    return self;
}

- (nullable PGPKeyMaterial *)fillMPIForPublic:(PGPPublicKeyPacket *)publicKeyPacket andSecret:(PGPSecretKeyPacket *)secretKeyPacket withKeyAlgorithm:(PGPPublicKeyAlgorithm)algorithm bits:(int)bits {
    PGPKeyMaterial *keyMaterial = nil;

    switch (algorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly: {
            keyMaterial = [PGPRSA generateNewKeyMPIArray:bits algorithm:algorithm];
            publicKeyPacket.publicMPIArray = @[keyMaterial.n, keyMaterial.e];
            secretKeyPacket.secretMPIArray = @[keyMaterial.d, keyMaterial.p, keyMaterial.q, keyMaterial.u];
        } break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA: {
            keyMaterial = [PGPDSA generateNewKeyMPIArray:bits algorithm:algorithm];
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

- (nullable PGPKey *)buildKey {
    let publicKeyPacket = [[PGPPublicKeyPacket alloc] init];
    publicKeyPacket.version = self.version;
    publicKeyPacket.publicKeyAlgorithm = self.keyAlgorithm;
    publicKeyPacket.createDate = self.createDate;

    // Secret Key
    let secretKeyPacket = [[PGPSecretKeyPacket alloc] init];
    secretKeyPacket.version = self.version;
    secretKeyPacket.publicKeyAlgorithm = publicKeyPacket.publicKeyAlgorithm;
    secretKeyPacket.s2kUsage = PGPS2KUsageNone;
    secretKeyPacket.s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSimple hashAlgorithm:PGPHashSHA1];
    secretKeyPacket.symmetricAlgorithm = self.symmetricAlgorithm;
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:secretKeyPacket.symmetricAlgorithm];
    secretKeyPacket.ivData = [NSMutableData dataWithLength:blockSize];
    secretKeyPacket.createDate = publicKeyPacket.createDate;

    [self fillMPIForPublic:publicKeyPacket andSecret:secretKeyPacket withKeyAlgorithm:self.keyAlgorithm bits:self.keyBitsLength];

    // Create Key
    let partialPublicKey = [[PGPPartialKey alloc] initWithPackets:@[publicKeyPacket]];
    let partialSecretKey = [[PGPPartialKey alloc] initWithPackets:@[secretKeyPacket]];
    let key = [[PGPKey alloc] initWithSecretKey:partialSecretKey publicKey:partialPublicKey];
    return key;
}

- (nullable PGPSignaturePacket *)buildPublicSignaturePacketFor:(PGPKey *)key {
    let publicKeyPacket = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);

    let publicKeySignaturePacket = [[PGPSignaturePacket alloc] init];
    publicKeySignaturePacket.version = publicKeyPacket.version;
    publicKeySignaturePacket.type = PGPSignatureGenericCertificationUserIDandPublicKey;
    publicKeySignaturePacket.publicKeyAlgorithm = publicKeyPacket.publicKeyAlgorithm;
    publicKeySignaturePacket.hashAlgoritm = self.hashAlgorithm;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:self.createDate];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowSignData), @(PGPSignatureFlagAllowCertifyOtherKeys)]];
    let preferredHashAlgorithmsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredHashAlgorithm andValue:@[@(PGPHashSHA256), @(PGPHashSHA384), @(PGPHashSHA512)]];
    let preferredSymetricAlgorithmsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm andValue:@[@(PGPSymmetricAES256), @(PGPSymmetricAES192), @(PGPSymmetricAES128), @(PGPSymmetricCAST5), @(PGPSymmetricTripleDES), @(PGPSymmetricIDEA)]];
    let preferredPreferredCompressionSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredCompressionAlgorithm andValue:@[@(PGPCompressionZLIB), @(PGPCompressionBZIP2), @(PGPCompressionZIP)]];
    let keyFeaturesSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeFeatures andValue:@[@(PGPFeatureModificationDetection)]];
    let keyServerPreferencesSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyServerPreference andValue:@[@(PGPKeyServerPreferenceNoModify)]];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:publicKeyPacket.keyID];
    let primaryUserIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePrimaryUserID andValue:@(YES)];

    publicKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket,
                                                  keyFlagsSubpacket,
                                                  preferredHashAlgorithmsSubpacket,
                                                  preferredSymetricAlgorithmsSubpacket,
                                                  preferredPreferredCompressionSubpacket,
                                                  keyFeaturesSubpacket,
                                                  keyServerPreferencesSubpacket,
                                                  primaryUserIDSubpacket];
    publicKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    NSError *error;
    let userID = key.publicKey.users.firstObject.userID;
    if (![publicKeySignaturePacket signData:nil usingKey:key passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return publicKeySignaturePacket;
}

- (nullable PGPSignaturePacket *)buildPublicSignaturePacketForSub:(PGPKey *)key {
    let publicKeyPacket = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);

    let publicKeySignaturePacket = [[PGPSignaturePacket alloc] init];
    publicKeySignaturePacket.version = publicKeyPacket.version;
    publicKeySignaturePacket.type = PGPSignatureSubkeyBinding;
    publicKeySignaturePacket.publicKeyAlgorithm = publicKeyPacket.publicKeyAlgorithm;
    publicKeySignaturePacket.hashAlgoritm = self.hashAlgorithm;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowEncryptCommunications), @(PGPSignatureFlagAllowEncryptStorage)]];
    let preferredHashAlgorithmsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredHashAlgorithm andValue:@[@(PGPHashSHA256), @(PGPHashSHA384), @(PGPHashSHA512)]];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:publicKeyPacket.keyID];

    publicKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket, keyFlagsSubpacket, preferredHashAlgorithmsSubpacket, issuerKeyIDSubpacket];
    publicKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    // self sign the signature
    NSError *error;
    let userID = key.publicKey.users.firstObject.userID;
    if (![publicKeySignaturePacket signData:nil usingKey:key passphrase:nil userID:userID error:&error]) {
        return nil;
    }

    return publicKeySignaturePacket;
}

- (NSData *)generateFor:(NSString *)userID {
    let key = [self buildKey];
    let subKey = [self buildKey];

    let userIDPacket = [[PGPUserIDPacket alloc] initWithUserID:userID];
    let user = [[PGPUser alloc] initWithUserIDPacket:userIDPacket];
    key.publicKey.users = @[user];
    key.secretKey.users = @[user];

    let publicKeySignaturePacket = [self buildPublicSignaturePacketFor:key];
    let publicSubKeySignaturePacket = [self buildPublicSignaturePacketForSub:subKey];

    NSError *error;
    let outputData = [NSMutableData data];
    [outputData appendData:[key.secretKey.primaryKeyPacket export:&error]];
    [outputData appendData:[userIDPacket export:&error]];
    [outputData appendData:[subKey.secretKey.primaryKeyPacket export:&error]];
    [outputData appendData:[key.publicKey.primaryKeyPacket export:&error]];
    [outputData appendData:[userIDPacket export:&error]];
    [outputData appendData:[publicKeySignaturePacket export:&error]];
    [outputData appendData:[publicSubKeySignaturePacket export:&error]];

    [outputData writeToFile:@"/Users/marcinkrzyzanowski/Devel/ObjectivePGP/test-key.dat" atomically:YES];

    return outputData;
}

@end

NS_ASSUME_NONNULL_END
