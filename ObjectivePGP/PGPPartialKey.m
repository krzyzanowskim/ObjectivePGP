//
//  PGPTransferableKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
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
#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPPartialKey ()

@property (nonatomic, readwrite) PGPPartialKeyType type;
@property (nonatomic, readwrite) BOOL isEncrypted;
@property (nonatomic, nullable, readwrite) NSDate *expirationDate;

@end

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
    return [NSString stringWithFormat:@"Type %@, %@ primary key: %@", self.type == PGPPartialKeyPublic ? @"public" : @"secret", [super description], self.primaryKeyPacket];
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

#pragma mark -

- (BOOL)isEncrypted {
    if (self.type == PGPPartialKeySecret) {
        return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket).isEncryptedWithPassphrase;
    }
    return NO;
}

- (nullable NSDate *)expirationDate {
    PGPSignaturePacket * _Nullable primaryUserSelfCertificate = nil;
    [self primaryUserAndSelfCertificate:&primaryUserSelfCertificate];
    if (primaryUserSelfCertificate.expirationDate) {
        return primaryUserSelfCertificate.expirationDate;
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        if (PGPEqualObjects(subKey.keyID,self.keyID)) {
            let _Nullable signaturePacket = subKey.bindingSignature;
            if (signaturePacket && signaturePacket.expirationDate) {
                return signaturePacket.expirationDate;
            }
        }
    }
    return nil;
}

- (PGPPartialKeyType)type {
    PGPPartialKeyType t = PGPPartialKeyUnknown;

    switch (self.primaryKeyPacket.tag) {
        case PGPPublicKeyPacketTag:
        case PGPPublicSubkeyPacketTag:
            t = PGPPartialKeyPublic;
            break;
        case PGPSecretKeyPacketTag:
        case PGPSecretSubkeyPacketTag:
            t = PGPPartialKeySecret;
            break;
        default:
            break;
    }

    return t;
}

- (void)loadPackets:(NSArray<PGPPacket *> *)packets {
    // based on packetlist2structure
    PGPKeyID *primaryKeyID;
    PGPPartialSubKey *subKey;
    PGPUser *user;

    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPPublicKeyPacketTag:
                primaryKeyID = PGPCast(packet, PGPPublicKeyPacket).keyID;
                self.primaryKeyPacket = [packet copy];
                break;
            case PGPSecretKeyPacketTag:
                primaryKeyID = PGPCast(packet, PGPPublicKeyPacket).keyID;
                self.primaryKeyPacket = [packet copy];
                break;
            case PGPUserAttributePacketTag:
                if (!user) {
                    continue;
                }
                user.userAttribute = PGPCast(packet, PGPUserAttributePacket);
                break;
            case PGPUserIDPacketTag: {
                let parsedUser = [[PGPUser alloc] initWithUserIDPacket:(PGPUserIDPacket *)packet];
                if (!user) {
                    user = parsedUser;
                }
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

    NSAssert(self.type == PGPPartialKeySecret, @"Need secret key to sign");
    if (self.type == PGPPartialKeyPublic) {
        PGPLogDebug(@"Need secret key to sign\n %@", [NSThread callStackSymbols]);
        return nil;
    }

    // check primary user self certificates
    PGPSignaturePacket *primaryUserSelfCertificate = nil;
    [self primaryUserAndSelfCertificate:&primaryUserSelfCertificate];
    if (primaryUserSelfCertificate) {
        if (primaryUserSelfCertificate.canBeUsedToSign) {
            return self.primaryKeyPacket;
        }
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToSign) {
            return subKey.primaryKeyPacket;
        }
    }

    // By convention, the top-level key provides signature services
    return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
}

// signature packet that is available for verifying signature with a keyID
- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID {
    // check primary user self certificates
    PGPSignaturePacket *primaryUserSelfCertificate = nil;
    [self primaryUserAndSelfCertificate:&primaryUserSelfCertificate];
    if (primaryUserSelfCertificate) {
        if (PGPEqualObjects(self.keyID,keyID)) {
            if (primaryUserSelfCertificate.canBeUsedToSign) {
                return self.primaryKeyPacket;
            }
        }
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        if (PGPEqualObjects(subKey.keyID,keyID)) {
            PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
            if (signaturePacket.canBeUsedToSign) {
                return subKey.primaryKeyPacket;
            }
        }
    }

    // By convention, the top-level key provides signature services
    return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
}

// signature packet that is available for signing data
- (nullable PGPPacket *)encryptionKeyPacket:(NSError *__autoreleasing *)error {
    NSAssert(self.type == PGPPartialKeyPublic, @"Need public key to encrypt");
    if (self.type == PGPPartialKeySecret) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Wrong key type, require public key" }];
        }
        PGPLogWarning(@"Need public key to encrypt");
        return nil;
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        let signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToEncrypt) {
            return subKey.primaryKeyPacket;
        }
    }

    // check primary user self certificates
    PGPSignaturePacket *primaryUserSelfCertificate = nil;
    [self primaryUserAndSelfCertificate:&primaryUserSelfCertificate];
    if (primaryUserSelfCertificate) {
        if (primaryUserSelfCertificate.canBeUsedToEncrypt) {
            return self.primaryKeyPacket;
        }
    }

    if (error) {
        *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Encryption key not found" }];
    }

    return nil;
}

- (nullable PGPSecretKeyPacket *)decryptionPacketForKeyID:(PGPKeyID *)keyID error:(NSError *__autoreleasing *)error {
    NSAssert(self.type == PGPPartialKeySecret, @"Need secret key to encrypt");
    if (self.type == PGPPartialKeyPublic) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Wrong key type, require secret key" }];
        }
        PGPLogWarning(@"Need public key to encrypt");
        return nil;
    }

    for (PGPPartialSubKey *subKey in self.subKeys) {
        let signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToEncrypt && PGPEqualObjects(PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket).keyID, keyID)) {
            return PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket);
        }
    }

    // assume primary key is always cabable
    if (PGPEqualObjects(PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket).keyID, keyID)) {
        return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
    }
    return nil;
}

// TODO: return error
- (nullable PGPPartialKey *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError *__autoreleasing *)error {
    let primarySecretPacket = PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
    if (!primarySecretPacket) {
        return nil;
    }

    // decrypt primary packet
    var decryptedPrimaryPacket = [primarySecretPacket decryptedWithPassphrase:passphrase error:error];
    if (!decryptedPrimaryPacket || *error) {
        return nil;
    }

    // decrypt subkeys packets
    for (PGPPartialSubKey *subKey in self.subKeys) {
        let subKeySecretPacket = PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket);
        if (subKeySecretPacket) {
            let subKeyDecryptedPacket = [subKeySecretPacket decryptedWithPassphrase:passphrase error:error];
            if (!subKeyDecryptedPacket || *error) {
                return nil;
            }
            subKey.primaryKeyPacket = subKeyDecryptedPacket;
        }
    }

    PGPPartialKey *partialKeyCopy = self.copy;
    partialKeyCopy.primaryKeyPacket = decryptedPrimaryPacket;

    return partialKeyCopy;
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
           self.isEncrypted == other.isEncrypted &&
           PGPEqualObjects(self.primaryKeyPacket, other.primaryKeyPacket) &&
           PGPEqualObjects(self.users, other.users) &&
           PGPEqualObjects(self.subKeys, other.subKeys) &&
           PGPEqualObjects(self.directSignatures, other.directSignatures) &&
           PGPEqualObjects(self.revocationSignature, other.revocationSignature) &&
           PGPEqualObjects(self.keyID, other.keyID);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + self.type;
    result = prime * result + self.isEncrypted;
    result = prime * result + self.primaryKeyPacket.hash;
    result = prime * result + self.users.hash;
    result = prime * result + self.subKeys.hash;
    result = prime * result + self.directSignatures.hash;
    result = prime * result + self.revocationSignature.hash;
    result = prime * result + self.keyID.hash;

    return result;
}

#pragma mark - NSCopying

-(instancetype)copyWithZone:(nullable NSZone *)zone {
    let partialKey = PGPCast([[self.class allocWithZone:zone] initWithPackets:@[]], PGPPartialKey);
    PGPAssertClass(partialKey, PGPPartialKey);

    partialKey.type = self.type;
    partialKey.primaryKeyPacket = [self.primaryKeyPacket copy];
    partialKey.isEncrypted = self.isEncrypted;
    partialKey.users = [[NSArray alloc] initWithArray:self.users copyItems:YES];
    partialKey.subKeys = [[NSArray alloc] initWithArray:self.subKeys copyItems:YES];
    partialKey.directSignatures = [[NSArray alloc] initWithArray:self.directSignatures copyItems:YES];
    partialKey.expirationDate = [self.expirationDate copy];
    return partialKey;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *_Nullable __autoreleasing *)error {
    let result = [NSMutableData data];

    for (PGPPacket *packet in self.allPacketsArray) {
        let exported = [packet export:error];
        if (!exported) {
            continue;
        }

        [result pgp_appendData:exported]; // TODO: decode secret key first
        if (error) {
            NSAssert(*error == nil, @"Error while export public key");
            if (*error) {
                return nil;
            }
        }
    }
    return result;
}

#pragma mark - Verification

// Returns primary user with self certificate
- (nullable PGPUser *)primaryUserAndSelfCertificate:(PGPSignaturePacket *__autoreleasing *)selfCertificateOut {
    PGPUser *foundUser = nil;

    for (PGPUser *user in self.users) {
        if (!user.userID || user.userID.length == 0) {
            continue;
        }

        let selfCertificate = [user validSelfCertificate:self];
        if (!selfCertificate) {
            continue;
        }

        if (selfCertificate.isPrimaryUserID) {
            foundUser = user;
        } else if (!foundUser) {
            foundUser = user;
        }
        *selfCertificateOut = selfCertificate;
    }
    return foundUser;
}

#pragma mark - Preferences

- (PGPSymmetricAlgorithm)preferredSymmetricAlgorithm {
    return [[self class] preferredSymmetricAlgorithmForKeys:@[self]];
}

+ (PGPSymmetricAlgorithm)preferredSymmetricAlgorithmForKeys:(NSArray<PGPPartialKey *> *)keys {
    // 13.2.  Symmetric Algorithm Preferences
    // Since TripleDES is the MUST-implement algorithm, if it is not explicitly in the list, it is tacitly at the end.

    let preferecesArray = [NSMutableArray<NSArray<NSNumber *> *> array];
    for (PGPPartialKey *key in keys) {
        let keyAlgorithms = [NSMutableArray<NSNumber *> array];

        PGPSignaturePacket *selfCertificate = nil;
        let primaryUser = [key primaryUserAndSelfCertificate:&selfCertificate];
        if (primaryUser && selfCertificate) {
            let signatureSubpacket = [[selfCertificate subpacketsOfType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm] firstObject];
            NSArray<NSNumber *> * _Nullable preferredSymetricAlgorithms = PGPCast(signatureSubpacket.value, NSArray);
            if (preferredSymetricAlgorithms) {
                [keyAlgorithms addObjectsFromArray:preferredSymetricAlgorithms];
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

    [arr addObject:self.primaryKeyPacket];

    if (self.revocationSignature) {
        [arr addObject:PGPNN(self.revocationSignature)];
    }

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
