//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPKey.h"
#import "PGPKey+Private.h"
#import "PGPPartialSubKey.h"
#import "PGPLogging.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

#import "PGPSecretKeyPacket.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPSignatureSubpacket+Private.h"
#import "PGPRSA.h"
#import "PGPDSA.h"
#import "PGPUser+Private.h"
#import "PGPUserIDPacket.h"


#import "NSMutableData+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPKey

- (instancetype)initWithSecretKey:(nullable PGPPartialKey *)secretKey publicKey:(nullable PGPPartialKey *)publicKey {
    if ((self = [super init])) {
        _secretKey = [secretKey copy];
        _publicKey = [publicKey copy];
    }
    return self;
}

- (BOOL)isSecret {
    return self.secretKey != nil;
}

- (BOOL)isPublic {
    return self.publicKey != nil;
}

- (BOOL)isEncryptedWithPassword {
    return self.publicKey.isEncryptedWithPassword || self.secretKey.isEncryptedWithPassword;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@\npublicKey: (%@)\nsecretKey: (%@)", super.description, self.publicKey, self.secretKey];
}

- (nullable NSDate *)expirationDate {
    return self.publicKey.expirationDate ?: self.secretKey.expirationDate;
}

- (PGPKeyID *)keyID {
    return self.publicKey.keyID ?: self.secretKey.keyID;
}

- (nullable PGPSecretKeyPacket *)signingSecretKey {
    if (!self.secretKey) {
        PGPLogDebug(@"Need secret key to sign");
        return nil;
    }

    // find secret key based on the public key signature (unless self signed secret key)
    let signingPacket = PGPCast(self.secretKey.signingKeyPacket, PGPSecretKeyPacket);
    if (!signingPacket) {
        PGPLogWarning(@"Need secret key to sign");
    }

    return signingPacket;
}

- (nullable PGPKey *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    let decryptedPartialKey = [self.secretKey decryptedWithPassphrase:passphrase error:error];
    if (decryptedPartialKey) {
        return [[PGPKey alloc] initWithSecretKey:decryptedPartialKey publicKey:self.publicKey];
    }
    return nil;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToKey:other];
    }
    return NO;
}

- (BOOL)isEqualToKey:(PGPKey *)other {
    return PGPEqualObjects(self.secretKey,other.secretKey) && PGPEqualObjects(self.publicKey,other.publicKey);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + self.secretKey.hash;
    result = prime * result + self.publicKey.hash;

    return result;
}

#pragma mark - Modifying Users

-(void)addUserId:(NSString*)userId  passphraseForKey:(nullable NSString * _Nullable(^NS_NOESCAPE)(PGPKey *key))passphraseBlock{
    if (self.secretKey){
        
        PGPUserIDPacket * packet = [PGPUserIDPacket.alloc initWithUserID:userId];
        PGPUser * secretUser = [PGPUser.alloc initWithUserIDPacket:packet];
        
        // selfCertify the user with the secret key
        let secretKeySignaturePacket = [self buildSignaturePacketForKeyPacket:self.secretKey.primaryKeyPacket
                                                                         user:secretUser
                                                                isPrimaryUser:NO
                                                             passphraseForKey:passphraseBlock];
        if (secretKeySignaturePacket){
            secretUser.selfCertifications = [secretUser.selfCertifications arrayByAddingObject:secretKeySignaturePacket];
        }
        
        NSMutableArray* muSecretUsers = [self.secretKey.users mutableCopy] ? : NSMutableArray.new;
        [muSecretUsers addObject:secretUser];
        self.secretKey.users = muSecretUsers.copy;
    }
    if (self.publicKey){
        
        PGPUserIDPacket * packet = [PGPUserIDPacket.alloc initWithUserID:userId];
        PGPUser * publicUser = [PGPUser.alloc initWithUserIDPacket:packet];
       
        // selfCertify the user with the public key
        let publicKeySignaturePacket = [self buildSignaturePacketForKeyPacket:self.publicKey.primaryKeyPacket
                                                                         user:publicUser
                                                                isPrimaryUser:NO
                                                             passphraseForKey:passphraseBlock];
        if (publicKeySignaturePacket){
            publicUser.selfCertifications = [publicUser.selfCertifications arrayByAddingObject:publicKeySignaturePacket];
        }
        
        NSMutableArray* muPublicUsers = [self.publicKey.users mutableCopy] ? : NSMutableArray.new;
        [muPublicUsers addObject:publicUser];
        self.publicKey.users = muPublicUsers.copy;
    }
}

-(void)removeUserId:(NSString*)userId{
    if (!userId) return;
    
    if (self.secretKey){
        let idxs = NSMutableIndexSet.new;
        [self.secretKey.users enumerateObjectsUsingBlock:^(PGPUser * _Nonnull user, NSUInteger idx, __unused BOOL * _Nonnull stop) {
            if ([userId isEqualToString:user.userID]) {
                [idxs addIndex:idx];
            }
        }];
        if (idxs.count){
            NSMutableArray* muSecretUsers = [self.secretKey.users mutableCopy] ? : NSMutableArray.new;
        
            [muSecretUsers removeObjectsAtIndexes:idxs];
            self.secretKey.users = muSecretUsers.copy;
        }
    }
    if (self.publicKey){
        let idxs = NSMutableIndexSet.new;
        [self.publicKey.users enumerateObjectsUsingBlock:^(PGPUser * _Nonnull user, NSUInteger idx, __unused BOOL * _Nonnull stop) {
            if ([userId isEqualToString:user.userID]) {
                [idxs addIndex:idx];
            }
        }];
        if (idxs.count){
            NSMutableArray* muPublicUsers = [self.publicKey.users mutableCopy] ? : NSMutableArray.new;
            [muPublicUsers removeObjectsAtIndexes:idxs];
            self.publicKey.users = muPublicUsers.copy;
        }
    }
}

- (NSArray<PGPSignatureSubpacket *> *)signatureCommonHashedSubpackets {
    return @[
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.new],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowSignData), @(PGPSignatureFlagAllowCertifyOtherKeys)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredHashAlgorithm andValue:@[@(PGPHashSHA256), @(PGPHashSHA384), @(PGPHashSHA512)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm andValue:@[@(PGPSymmetricAES256), @(PGPSymmetricAES192), @(PGPSymmetricAES128), @(PGPSymmetricCAST5), @(PGPSymmetricTripleDES), @(PGPSymmetricIDEA)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredCompressionAlgorithm andValue:@[@(PGPCompressionZLIB), @(PGPCompressionZIP), @(PGPCompressionBZIP2)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeFeatures andValue:@[@(PGPFeatureModificationDetection)]],
             [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyServerPreference andValue:@[@(PGPKeyServerPreferenceNoModify)]]
             
     ];
}


- (nullable PGPSignaturePacket *)buildSignaturePacketForKeyPacket:(PGPPacket*)packet
                                                             user:(PGPUser*)user
                                                    isPrimaryUser:(BOOL)isPrimary
                                                 passphraseForKey:(nullable NSString * _Nullable(^NS_NOESCAPE)(PGPKey *key))passphraseBlock{
    let keyPacket = PGPCast(packet,PGPPublicKeyPacket);
   
    if (!keyPacket){
        return nil;
    }
    
    let signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignaturePositiveCertificationUserIDandPublicKey hashAlgorithm:PGPHashSHA256];
    signaturePacket.version = keyPacket.version;
    signaturePacket.publicKeyAlgorithm = keyPacket.publicKeyAlgorithm;

    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:keyPacket.keyID];
    let fingerprintSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerFingerprint andValue:[keyPacket.fingerprint exportV4HashedData]];
    var preferredKeyServer = (PGPSignatureSubpacket*)nil;
    
    NSMutableArray * hashedSubPackets = [self.signatureCommonHashedSubpackets mutableCopy]?:NSMutableArray.new;
    
    [hashedSubPackets addObject:[[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePrimaryUserID andValue:@(isPrimary)]];
    
    
    signaturePacket.hashedSubpackets = hashedSubPackets.copy;

    if (preferredKeyServer){
        signaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket, fingerprintSubpacket,preferredKeyServer];
    }
    else{
        signaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket, fingerprintSubpacket];
    }

    // self sign the signature -- requires passphrase
    NSError *error;
    let userID = user.userID;
    
    let passPhrase = passphraseBlock ? passphraseBlock(self) : nil;
    
    if (![signaturePacket signData:nil withKey:self subKey:nil passphrase:passPhrase userID:userID error:&error]) {
        return nil;
    }

    return signaturePacket;

}




#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([[self.class allocWithZone:zone] initWithSecretKey:self.secretKey publicKey:self.publicKey], PGPKey);
    return duplicate;
}

#pragma mark - PGPExportable

/// Export public and secret keys together.
- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    let exportData = [NSMutableData data];
    if (self.publicKey) {
        [exportData pgp_appendData:[self export:PGPKeyTypePublic error:error]];
    }

    if (self.secretKey) {
        [exportData pgp_appendData:[self export:PGPKeyTypeSecret error:error]];
    }

    return exportData;
}

- (nullable NSData *)export:(PGPKeyType)keyType error:(NSError * __autoreleasing _Nullable *)error {
    switch (keyType) {
        case PGPKeyTypePublic: {
            if (!self.publicKey) {
                return nil;
            }

            return [self.publicKey export:error];
        }
        break;
        case PGPKeyTypeSecret: {
            if (!self.secretKey) {
                return nil;
            }

            return [self.secretKey export:error];
        }
        break;
        default: {
            PGPLogDebug(@"Can't export unknown key type: %@", self);
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Can't export unknown key type"}];
            }
        }
        break;
    }

    return nil;
}

@end

NS_ASSUME_NONNULL_END
