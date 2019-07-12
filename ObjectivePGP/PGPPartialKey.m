//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPartialKey.h"
#import "PGPPartialKey+Private.h"
#import "PGPLogging.h"
#import "PGPPublicKeyPacket.h"
#import "PGPPublicSubKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSecretSubKeyPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPSignatureSubpacket.h"
#import "PGPPartialSubKey.h"
#import "PGPPartialSubKey+Private.h"
#import "PGPUser.h"
#import "PGPUser+Private.h"
#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"
#import "NSMutableData+PGPUtils.h"
#import "NSArray+PGPUtils.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPartialKey

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets {
    if ((self = [super init])) {
        _subKeys = [NSArray<PGPPartialSubKey *> array];
        _directSignatures = [NSArray<PGPSignaturePacket *> array];
        _users = [NSArray<PGPUser *> array];
        [self loadPackets:packets];
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, Type %@, primary key: %@", [super description], self.type == PGPKeyTypePublic ? @"public" : @"secret", self.primaryKeyPacket];
}

#pragma mark - Properties

- (PGPKeyID *)keyID {
    let primaryKeyPacket = PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket);
    NSParameterAssert(primaryKeyPacket);
    return [[PGPKeyID alloc] initWithFingerprint:primaryKeyPacket.fingerprint];
}

- (PGPFingerprint *)fingerprint {
    let primaryKeyPacket = PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket);
    NSParameterAssert(primaryKeyPacket);
    return primaryKeyPacket.fingerprint;
}

- (BOOL)isEncryptedWithPassword {
    if (self.type == PGPKeyTypeSecret) {
        return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket).isEncryptedWithPassphrase;
    }
    return NO;
}

// Key expiration date
- (nullable NSDate *)expirationDate {
    let _Nullable primaryUserSelfCertificate = self.primaryUserSelfCertificate;
    if (primaryUserSelfCertificate && primaryUserSelfCertificate.expirationDate) {
        return primaryUserSelfCertificate.expirationDate;
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        let _Nullable bindingSignaturePacket = subKey.bindingSignature;
        if (!bindingSignaturePacket.isExpired && bindingSignaturePacket && PGPEqualObjects(bindingSignaturePacket.issuerKeyID,self.keyID)) {
            // key expiration
            // PGPSignatureSubpacketTypeKeyExpirationTime - This is found only on a self-signature.
            // A self-signature is a binding signature made by the key to which the signature refers.
            var validityPeriodSubpacket = PGPCast([bindingSignaturePacket subpacketsOfType:PGPSignatureSubpacketTypeKeyExpirationTime].lastObject, PGPSignatureSubpacket);
            let validityPeriod = PGPCast(validityPeriodSubpacket.value, NSNumber);
            if (!validityPeriod || validityPeriod.unsignedIntegerValue == 0) {
                return nil;
            }

            let _Nullable keyPacket = PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket);
            if (keyPacket) {
                return [keyPacket.createDate dateByAddingTimeInterval:validityPeriod.unsignedIntegerValue];
            }
        }
    }
    return nil;
}

#pragma mark -

- (PGPKeyType)type {
    PGPKeyType t = PGPKeyTypeUnknown;

    switch (self.primaryKeyPacket.tag) {
        case PGPPublicKeyPacketTag:
        case PGPPublicSubkeyPacketTag:
            t = PGPKeyTypePublic;
            break;
        case PGPSecretKeyPacketTag:
        case PGPSecretSubkeyPacketTag:
            t = PGPKeyTypeSecret;
            break;
        default:
            break;
    }

    return t;
}

- (void)loadPackets:(NSArray<PGPPacket *> *)packets {
    PGPKeyID *primaryKeyID;
    PGPPartialSubKey *subKey;

    // Current "context" user. The last parsed user packet.
    PGPUser *user;

    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPPublicKeyPacketTag:
                primaryKeyID = PGPCast(packet, PGPPublicKeyPacket).keyID;
                self.primaryKeyPacket = packet;
                break;
            case PGPSecretKeyPacketTag:
                primaryKeyID = PGPCast(packet, PGPPublicKeyPacket).keyID;
                self.primaryKeyPacket = packet;
                break;
            case PGPUserAttributePacketTag:
                if (!user) {
                    continue;
                }
                user.userAttribute = PGPCast(packet, PGPUserAttributePacket);
                break;
            case PGPUserIDPacketTag: {
                let parsedUser = [[PGPUser alloc] initWithUserIDPacket:PGPCast(packet, PGPUserIDPacket)];
                user = parsedUser;
                self.users = [self.users arrayByAddingObject:parsedUser];
            } break;
            case PGPPublicSubkeyPacketTag:
            case PGPSecretSubkeyPacketTag:
                user = nil;
                subKey = [[PGPPartialSubKey alloc] initWithPacket:packet];
                self.subKeys = [self.subKeys arrayByAddingObject:subKey];
                break;
            case PGPSignaturePacketTag: {
                let signaturePacket = PGPCast(packet, PGPSignaturePacket);
                PGPAssertClass(signaturePacket, signaturePacket);
                switch (signaturePacket.type) {
                    case PGPSignatureGenericCertificationUserIDandPublicKey:
                    case PGPSignatureCasualCertificationUserIDandPublicKey:
                    case PGPSignaturePositiveCertificationUserIDandPublicKey:
                    case PGPSignaturePersonalCertificationUserIDandPublicKey:
                        if (!user) {
                            continue;
                        }
                        if (PGPEqualObjects(signaturePacket.issuerKeyID,primaryKeyID)) {
                            user.selfCertifications = [user.selfCertifications arrayByAddingObject:signaturePacket];
                        } else {
                            user.otherSignatures = [user.otherSignatures arrayByAddingObject:signaturePacket];
                        }
                        break;
                    case PGPSignatureCertificationRevocation:
                        if (user) {
                            user.revocationSignatures = [user.revocationSignatures arrayByAddingObject:signaturePacket];
                        } else {
                            self.directSignatures = [self.directSignatures arrayByAddingObject:signaturePacket];
                        }
                        break;
                    case PGPSignatureDirectlyOnKey:
                        self.directSignatures = [self.directSignatures arrayByAddingObject:signaturePacket];
                        break;
                    case PGPSignatureSubkeyBinding:
                        if (!subKey) {
                            continue;
                        }

                        // TODO: check embedded signature "PGPSignaturePrimaryKeyBinding"
                        // A signature that binds a signing subkey MUST have
                        // an Embedded Signature subpacket in this binding signature that
                        // contains a 0x19 signature made by the signing subkey on the
                        // primary key and subkey.

                        subKey.bindingSignature = PGPCast(packet, PGPSignaturePacket);
                        break;
                    case PGPSignatureKeyRevocation:
                        self.revocationSignature = PGPCast(packet, PGPSignaturePacket);
                        break;
                    case PGPSignatureSubkeyRevocation:
                        if (!subKey) {
                            continue;
                        }
                        subKey.revocationSignature = PGPCast(packet, PGPSignaturePacket);
                        break;
                    default:
                        break;
                }
            } break;
            default:
                break;
        }
    }
}

// signature packet that is available for signing data
- (nullable PGPPacket *)signingKeyPacket {
    //  It's private key for sign and public for verify as so thi can't be checked here

    NSAssert(self.type == PGPKeyTypeSecret, @"Need secret key to sign");
    if (self.type == PGPKeyTypePublic) {
        PGPLogDebug(@"Need secret key to sign\n %@", [NSThread callStackSymbols]);
        return nil;
    }

    // Favor subkey over primary key.
    // check subkeys, by default first check the subkeys
    for (PGPPartialSubKey *subKey in self.subKeys) {
        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToSign) {
            return subKey.primaryKeyPacket;
        }
    }

    // check primary user self certificates
    let _Nullable primaryUserSelfCertificate = self.primaryUserSelfCertificate;
    if (primaryUserSelfCertificate && primaryUserSelfCertificate.canBeUsedToSign) {
        return self.primaryKeyPacket;
    }

    // By convention, the top-level key provides signature services
    return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
}

// signature packet that is available for verifying signature with a keyID
- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID {
    for (PGPPartialSubKey *subKey in self.subKeys) {
        if (PGPEqualObjects(subKey.keyID,keyID)) {
            PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
            if (signaturePacket.canBeUsedToSign) {
                return subKey.primaryKeyPacket;
            }
        }
    }

    // check primary user self certificates
    let _Nullable primaryUserSelfCertificate = self.primaryUserSelfCertificate;
    if (primaryUserSelfCertificate && PGPEqualObjects(self.keyID,keyID)) {
        if (primaryUserSelfCertificate.canBeUsedToSign) {
            return self.primaryKeyPacket;
        }
    }

    // By convention, the top-level key provides signature services
    return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
}

// signature packet that is available for signing data
- (nullable PGPPacket *)encryptionKeyPacket:(NSError * __autoreleasing *)error {
    NSAssert(self.type == PGPKeyTypePublic, @"Need public key to encrypt");
    if (self.type == PGPKeyTypeSecret) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Wrong key type, require public key" }];
        }
        PGPLogDebug(@"Need public key to encrypt");
        return nil;
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        let bindingSignature = subKey.bindingSignature;
        if (bindingSignature.canBeUsedToEncrypt) {
            return subKey.primaryKeyPacket;
        }
    }

    // check primary user self certificates
    let _Nullable primaryUserSelfCertificate = self.primaryUserSelfCertificate;
    if (primaryUserSelfCertificate && primaryUserSelfCertificate.canBeUsedToEncrypt) {
        return self.primaryKeyPacket;
    }

    // v3 keys MUST NOT have subkeys
    if (PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket).version >= 0x04) {
        // 5.5.1.2. If not specified otherwise,
        // By convention, the subkeys provide encryption services.
        return PGPCast(self.subKeys.firstObject.primaryKeyPacket, PGPPublicSubKeyPacket);;
    }

    if (error) {
        *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Encryption key not found" }];
    }

    return nil;
}

- (nullable PGPSecretKeyPacket *)decryptionPacketForKeyID:(PGPKeyID *)keyID error:(NSError * __autoreleasing _Nullable *)error {
    NSAssert(self.type == PGPKeyTypeSecret, @"Need secret key to encrypt");
    if (self.type == PGPKeyTypePublic) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Wrong key type, require secret key" }];
        }
        PGPLogDebug(@"Need public key to encrypt");
        return nil;
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        let signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToEncrypt && PGPEqualObjects(PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket).keyID, keyID)) {
            return PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket);
        }
    }

    // assume primary key is always capable
    if (PGPEqualObjects(PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket).keyID, keyID)) {
        return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
    }
    return nil;
}

// TODO: return error
- (nullable PGPPartialKey *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(passphrase, NSString);

    // decrypt copy of self
    let encryptedPartialKey = PGPCast(self.copy, PGPPartialKey);
    PGPAssertClass(encryptedPartialKey, PGPPartialKey);

    let primarySecretPacket = PGPCast(encryptedPartialKey.primaryKeyPacket, PGPSecretKeyPacket);
    if (!primarySecretPacket) {
        return nil;
    }

    // decrypt primary packet
    var decryptedPrimaryPacket = [primarySecretPacket decryptedWithPassphrase:passphrase error:error];
    if (!decryptedPrimaryPacket || *error) {
        return nil;
    }

    // decrypt subkeys packets
    for (PGPPartialSubKey *subKey in encryptedPartialKey.subKeys) {
        let subKeySecretPacket = PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket);
        if (subKeySecretPacket) {
            let subKeyDecryptedPacket = [subKeySecretPacket decryptedWithPassphrase:passphrase error:error];
            if (!subKeyDecryptedPacket || *error) {
                return nil;
            }
            subKey.primaryKeyPacket = [subKeyDecryptedPacket copy];
        }
    }

    encryptedPartialKey.primaryKeyPacket = decryptedPrimaryPacket;
    return encryptedPartialKey;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToPartialKey:other];
    }
    return NO;
}

- (BOOL)isEqualToPartialKey:(PGPPartialKey *)other {
    return self.type == other.type &&
           PGPEqualObjects(self.primaryKeyPacket, other.primaryKeyPacket) &&
           PGPEqualObjects(self.users, other.users) &&
           PGPEqualObjects(self.subKeys, other.subKeys) &&
           PGPEqualObjects(self.directSignatures, other.directSignatures) &&
           PGPEqualObjects(self.revocationSignature, other.revocationSignature);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + self.type;
    result = prime * result + self.primaryKeyPacket.hash;
    result = prime * result + self.users.hash;
    result = prime * result + self.subKeys.hash;
    result = prime * result + self.directSignatures.hash;
    result = prime * result + self.revocationSignature.hash;

    return result;
}

#pragma mark - NSCopying

-(instancetype)copyWithZone:(nullable NSZone *)zone {
    let partialKey = PGPCast([[self.class allocWithZone:zone] initWithPackets:@[]], PGPPartialKey);
    PGPAssertClass(partialKey, PGPPartialKey);

    partialKey.type = self.type;
    partialKey.primaryKeyPacket = self.primaryKeyPacket;
    partialKey.users = [[NSArray alloc] initWithArray:self.users copyItems:YES];
    partialKey.subKeys = [[NSArray alloc] initWithArray:self.subKeys copyItems:YES];
    partialKey.directSignatures = [[NSArray alloc] initWithArray:self.directSignatures copyItems:YES];
    partialKey.revocationSignature = self.revocationSignature;
    return partialKey;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    let result = [NSMutableData data];

    for (PGPPacket *packet in self.allPacketsArray) {
        let exported = [packet export:error];
        if (!exported) {
            continue;
        }

        [result pgp_appendData:exported]; // TODO: decode secret key first
        if (error && *error) {
            PGPLogDebug(@"Problem while export public key: %@", [*error localizedDescription]);
            return nil;
        }
    }
    return result;
}

#pragma mark - Verification

- (nullable PGPUser *)primaryUser {
    let _Nullable primaryUsers = [[self.users pgp_objectsPassingTest:^BOOL(PGPUser *user, BOOL *stop) {
        return user.userID && user.userID.length > 0;
    }] pgp_flatMap:^NSArray * _Nullable (PGPUser *user) {
        let _Nullable latestSelfCertificate = user.latestSelfCertificate;
        if (latestSelfCertificate && latestSelfCertificate.isPrimaryUserID) {
            return @[user];
        }
        return nil;
    }];

    // no selected primary users here and only one user? that's the primary one
    if (primaryUsers.count == 0 && self.users.count == 1) {
        return self.users.firstObject;
    }

    // it is RECOMMENDED that priority be given to the User ID with the most recent self-signature
    // Sort the primary users, or all users if there's no primary user selected.
    let users = primaryUsers.count > 0 ? primaryUsers : self.users;
    let sortedPrimaryUsers = [users sortedArrayUsingComparator:^NSComparisonResult(PGPUser *lhs, PGPUser *rhs) {
        let _Nullable LHSLatestSelfCertificateExpirationDate = lhs.latestSelfCertificate.expirationDate;
        let _Nullable RHSLatestSelfCertificateExpirationDate = rhs.latestSelfCertificate.expirationDate;

        if (LHSLatestSelfCertificateExpirationDate && RHSLatestSelfCertificateExpirationDate) {
            return [PGPNN(LHSLatestSelfCertificateExpirationDate) compare:PGPNN(RHSLatestSelfCertificateExpirationDate)];
        }
        return NSOrderedSame;
    }];

    return sortedPrimaryUsers.lastObject;
}

- (nullable PGPSignaturePacket *)primaryUserSelfCertificate {
    return self.primaryUser.latestSelfCertificate;
}

#pragma mark - Preferences

- (PGPSymmetricAlgorithm)preferredSymmetricAlgorithm {
    return [self.class preferredSymmetricAlgorithmForKeys:@[self]];
}

+ (PGPSymmetricAlgorithm)preferredSymmetricAlgorithmForKeys:(NSArray<PGPPartialKey *> *)keys {
    // 13.2.  Symmetric Algorithm Preferences
    // Since TripleDES is the MUST-implement algorithm, if it is not explicitly in the list, it is tacitly at the end.

    let preferecesArray = [NSMutableArray<NSArray<NSNumber *> *> array];
    for (PGPPartialKey *key in keys) {
        let keyAlgorithms = [NSMutableArray<NSNumber *> array];

        let _Nullable primaryUserSelfCertificate = key.primaryUserSelfCertificate;
        if (key.primaryUser && primaryUserSelfCertificate) {
            let signatureSubpacket = [[primaryUserSelfCertificate subpacketsOfType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm] firstObject];
            NSArray<NSNumber *> * _Nullable preferredSymetricAlgorithms = PGPCast(signatureSubpacket.value, NSArray);
            if (preferredSymetricAlgorithms) {
                [keyAlgorithms addObjectsFromArray:PGPNN(preferredSymetricAlgorithms)];
            }
        }

        if (keyAlgorithms.count > 0) {
            [preferecesArray addObject:keyAlgorithms];
        }
    }

    // intersect
    if (preferecesArray.count > 0) {
        let set = [NSMutableOrderedSet<NSNumber *> orderedSetWithArray:preferecesArray[0]];
        for (NSArray<NSNumber *> *prefArray in preferecesArray) {
            [set intersectSet:[NSSet setWithArray:prefArray]];
        }
        return (PGPSymmetricAlgorithm)[set[0] unsignedIntValue];
    }

    return PGPSymmetricTripleDES;
}

#pragma mark - Private

/**
 *  Ordered list of packets. Trust Packet is not exported.
 *
 *  @return array
 */
- (NSArray<PGPPacket *> *)allPacketsArray {
    // TODO: handle trust packet somehow. The Trust packet is used only within keyrings and is not normally exported.
    let arr = [NSMutableArray<PGPPacket *> array];

    [arr pgp_addObject:self.primaryKeyPacket];
    [arr pgp_addObject:self.revocationSignature];

    for (PGPSignaturePacket *packet in self.directSignatures) {
        [arr addObject:packet];
    }

    for (PGPUser *user in self.users) {
        [arr addObjectsFromArray:[user allPackets]];
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        [arr addObjectsFromArray:[subKey allPackets]];
    }

    return arr;
}

- (NSArray<PGPPacket *> *)allKeyPackets {
    let arr = [NSMutableArray<PGPPacket *> arrayWithObject:self.primaryKeyPacket];
    for (PGPPartialSubKey *subKey in self.subKeys) {
        [arr addObject:subKey.primaryKeyPacket];
    }
    return arr;
}

@end

NS_ASSUME_NONNULL_END
