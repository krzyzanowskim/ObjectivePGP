//
//  PGPTransferableKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPUser.h"
#import "PGPSignaturePacket.h"
#import "PGPSignatureSubpacket.h"
#import "PGPPublicSubKeyPacket.h"
#import "PGPSecretSubKeyPacket.h"
#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"
#import "PGPSubKey.h"
#import "NSValue+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPKey

- (instancetype) initWithPackets:(NSArray<PGPPacket *> *)packets
{
    if (self = [self init]) {
        _subKeys = [NSArray<PGPSubKey *> array];
        _directSignatures = [NSArray<PGPSignaturePacket *> array];
        _users = [NSArray<PGPUser *> array];
        [self loadPackets:packets];
    }
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"Type %@, %@ primary key: %@",self.type == PGPKeyPublic ? @"public" : @"secret", [super description], self.primaryKeyPacket];
}

- (BOOL)isEqual:(id)object
{
    if (self == object) {
        return YES;
    }
    
    if (![object isKindOfClass:PGPKey.class]) {
        return NO;
    }
    
    //TODO: check all properties
    let objectKey = PGPCast(object, PGPKey);
    return [self.keyID isEqual:objectKey.keyID] && (self.type == objectKey.type);
}

- (NSUInteger)hash
{
#ifndef NSUINTROTATE
#define NSUINT_BIT (CHAR_BIT * sizeof(NSUInteger))
#define NSUINTROTATE(val, howmuch) ((((NSUInteger)val) << howmuch) | (((NSUInteger)val) >> (NSUINT_BIT - howmuch)))
#endif
    
    NSUInteger hash = [self.primaryKeyPacket hash];
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ self.type;
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ [self.users hash];
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ [self.subKeys hash];
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ [self.directSignatures hash];
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ [self.revocationSignature hash];
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ [self.keyID hash];
    
    return hash;
}

- (BOOL)isEncrypted
{
    if (self.type == PGPKeySecret) {
        PGPSecretKeyPacket *secretPacket = (PGPSecretKeyPacket *)self.primaryKeyPacket;
        return secretPacket.isEncryptedWithPassword;
    }
    return NO;
}

- (PGPKeyType)type
{
    PGPKeyType t = PGPKeyUnknown;
    
    switch (self.primaryKeyPacket.tag) {
        case PGPPublicKeyPacketTag:
        case PGPPublicSubkeyPacketTag:
            t = PGPKeyPublic;
            break;
        case PGPSecretKeyPacketTag:
        case PGPSecretSubkeyPacketTag:
            t = PGPKeySecret;
        default:
            break;
    }
    
    return t;
}

- (PGPKeyID *)keyID {
    let primaryKeyPacket = PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket);
    let keyID = [[PGPKeyID alloc] initWithFingerprint:primaryKeyPacket.fingerprint];
    return keyID;
}

- (void) loadPackets:(NSArray<PGPPacket *> *)packets
{
    // based on packetlist2structure
    PGPKeyID *primaryKeyID;
    PGPSubKey *subKey;
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
            case PGPUserIDPacketTag:
            {
                PGPUser *parsedUser = [[PGPUser alloc] initWithUserIDPacket:(PGPUserIDPacket *)packet];
                if (!user) {
                    user = parsedUser;
                }
                self.users = [self.users arrayByAddingObject:parsedUser];
            }
                break;
            case PGPPublicSubkeyPacketTag:
            case PGPSecretSubkeyPacketTag:
                user = nil;
                subKey = [[PGPSubKey alloc] initWithPacket:packet];
                self.subKeys = [self.subKeys arrayByAddingObject:subKey];
                break;
            case PGPSignaturePacketTag:
            {
                let signaturePacket = PGPCast(packet, PGPSignaturePacket);
                switch (signaturePacket.type) {
                    case PGPSignatureGenericCertificationUserIDandPublicKey:
                    case PGPSignatureCasualCertificationUserIDandPublicKey:
                    case PGPSignaturePositiveCertificationUserIDandPublicKey:
                    case PGPSignaturePersonalCertificationUserIDandPublicKey:
                        if (!user) {
                            continue;
                        }
                        if ([signaturePacket.issuerKeyID isEqual:primaryKeyID]) {
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
                        self.revocationSignature = PGPCast(packet,PGPSignaturePacket);
                        break;
                    case PGPSignatureSubkeyRevocation:
                        if (!subKey) {
                            continue;
                        }
                        subKey.revocationSignature = PGPCast(packet,PGPSignaturePacket);
                        break;
                    default:
                        break;
                }
            }
                break;
            default:
                break;
        }
    }
}

// signature packet that is available for signing data
- (nullable PGPPacket *)signingKeyPacket {
    //  It's private key for sign and public for verify as so thi can't be checked here
    
    NSAssert(self.type == PGPKeySecret, @"Need secret key to sign");
    if (self.type == PGPKeyPublic) {
        PGPLogDebug(@"Need secret key to sign\n %@",[NSThread callStackSymbols]);
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

    for (PGPSubKey *subKey in self.subKeys) {
        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToSign) {
            return subKey.primaryKeyPacket;
        }
    }
    
    return nil;
}

// signature packet that is available for verifying signature with a keyID
- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID
{
    // check primary user self certificates
    PGPSignaturePacket *primaryUserSelfCertificate = nil;
    [self primaryUserAndSelfCertificate:&primaryUserSelfCertificate];
    if (primaryUserSelfCertificate)
    {
        if ([self.keyID isEqualToKeyID:keyID])
        {
            if (primaryUserSelfCertificate.canBeUsedToSign) {
                return self.primaryKeyPacket;
            }
        }
    }
    
    for (PGPSubKey *subKey in self.subKeys) {
        if ([subKey.keyID isEqualToKeyID:keyID])
        {
            PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
            if (signaturePacket.canBeUsedToSign) {
                return subKey.primaryKeyPacket;
            }
        }
    }
    
    return nil;
}

// signature packet that is available for signing data
- (nullable PGPPacket *)encryptionKeyPacket:(NSError * __autoreleasing *)error
{
    NSAssert(self.type == PGPKeyPublic, @"Need public key to encrypt");
    if (self.type == PGPKeySecret) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Wrong key type, require public key"}];
        }
        PGPLogWarning(@"Need public key to encrypt");
        return nil;
    }
    
    for (PGPSubKey *subKey in self.subKeys) {
        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
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
        *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Encryption key not found"}];
    }

    return nil;
}

- (nullable PGPSecretKeyPacket *)decryptionKeyPacketWithID:(PGPKeyID *)keyID error:(NSError * __autoreleasing *)error
{
    NSAssert(self.type == PGPKeySecret, @"Need secret key to encrypt");
    if (self.type == PGPKeyPublic) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Wrong key type, require secret key"}];
        }
        PGPLogWarning(@"Need public key to encrypt");
        return nil;
    }
    
    for (PGPSubKey *subKey in self.subKeys) {
        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToEncrypt && [((PGPSecretKeyPacket *)subKey.primaryKeyPacket).keyID isEqualToKeyID:keyID]) {
            return PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket);
        }
    }
    
    // assume primary key is always cabable
    if ([PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket).keyID isEqualToKeyID:keyID]) {
        return PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
    }
    return nil;
}

// Note: After decryption encrypted packets are replaced with new decrypted instances on key.
//TODO: return error
- (BOOL)decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error {
    let primarySecretPacket = PGPCast(self.primaryKeyPacket, PGPSecretKeyPacket);
    if (!primarySecretPacket) {
        return NO;
    }

    // decrypt primary packet
    var decryptedPrimaryPacket = [primarySecretPacket decryptedKeyPacket:passphrase error:error];
    if (!decryptedPrimaryPacket) {
        return NO;
    }

    // decrypt subkeys packets
    for (PGPSubKey *subKey in self.subKeys) {
        let subKeySecretPacket = PGPCast(subKey.primaryKeyPacket, PGPSecretKeyPacket);
        if (subKeySecretPacket) {
            let subKeyDecryptedPacket = [subKeySecretPacket decryptedKeyPacket:passphrase error:error];
            if (!subKeyDecryptedPacket) {
                return NO;
            }
            subKey.primaryKeyPacket = subKeyDecryptedPacket;
        }
    }

    self.primaryKeyPacket = decryptedPrimaryPacket;
    return YES;
}

- (NSData *)export:(NSError *__autoreleasing *)error {
    NSMutableData *result = [NSMutableData data];

    for (PGPPacket * packet in self.allPacketsArray) {
        [result appendData:[packet exportPacket:error]]; //TODO: decode secret key first
        if (error) {
            NSAssert(*error == nil,@"Error while export public key");
            if (*error) {
                return nil;
            }
        }
    }
    return [result copy];
}

#pragma mark - Verification

// Returns primary user with self certificate
- (PGPUser *)primaryUserAndSelfCertificate:(PGPSignaturePacket * __autoreleasing *)selfCertificateOut
{
    PGPUser *foundUser = nil;

    for (PGPUser *user in self.users) {
        if (!user.userID || user.userID.length == 0) {
            continue;
        }

        PGPSignaturePacket *selfCertificate = [user validSelfCertificate:self];
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

- (PGPSymmetricAlgorithm) preferredSymmetricAlgorithm
{
    return [[self class] preferredSymmetricAlgorithmForKeys:@[self]];
}

+ (PGPSymmetricAlgorithm) preferredSymmetricAlgorithmForKeys:(NSArray<PGPKey *> *)keys
{
    // 13.2.  Symmetric Algorithm Preferences
    // Since TripleDES is the MUST-implement algorithm, if it is not explicitly in the list, it is tacitly at the end.

    let preferecesArray = [NSMutableArray<NSArray<NSNumber *> *> array];
    for (PGPKey *key in keys) {
        let keyAlgorithms = [NSMutableArray<NSNumber *> array];
        
        PGPSignaturePacket *selfCertificate = nil;
        PGPUser *primaryUser = [key primaryUserAndSelfCertificate:&selfCertificate];
        if (primaryUser && selfCertificate) {
            PGPSignatureSubpacket *subpacket = [[selfCertificate subpacketsOfType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm] firstObject];
            NSArray *preferencesArray = subpacket.value;
            for (NSValue *preferedValue in preferencesArray) {
                if ([preferedValue pgp_objCTypeIsEqualTo:@encode(PGPSymmetricAlgorithm)]) {
                    PGPSymmetricAlgorithm algorithm = PGPSymmetricPlaintext;
                    [preferedValue getValue:&algorithm];
                    [keyAlgorithms addObject:@(algorithm)];
                }
            }
        }
        
        if (keyAlgorithms.count > 0) {
            [preferecesArray addObject:keyAlgorithms];
        }
    }
    
    // intersect
    if (preferecesArray.count > 0) {
        let set = [NSMutableOrderedSet<NSNumber *> orderedSetWithArray:preferecesArray[0]];
        for (NSArray *prefArray in preferecesArray) {
            [set intersectSet:[NSSet setWithArray:prefArray]];
        }
        return [set[0] unsignedIntValue];
    }
    
    return PGPSymmetricTripleDES;
}

#pragma mark - Private

/**
 *  Ordered list of packets. Trust Packet is not exported.
 *
 *  @return array
 */
- (NSArray<PGPPacket *> *)allPacketsArray
{
    //TODO: handle trust packet somehow. The Trust packet is used only within keyrings and is not normally exported.
    let arr = [NSMutableArray<PGPPacket *> array];

    [arr addObject:self.primaryKeyPacket];

    if (self.revocationSignature) {
        [arr addObject:self.revocationSignature];
    }

    for (id packet in self.directSignatures) {
        [arr addObject:packet];
    }

    for (PGPUser *user in self.users) {
        [arr addObjectsFromArray:[user allPackets]];
    }

    for (PGPSubKey *subKey in self.subKeys) {
        [arr addObjectsFromArray:[subKey allPackets]];
    }

    return arr;
}

- (NSArray<PGPPacket *> *)allKeyPackets
{
    let arr = [NSMutableArray<PGPPacket *> arrayWithObject:self.primaryKeyPacket];
    for (PGPSubKey *subKey in self.subKeys) {
        [arr addObject:subKey.primaryKeyPacket];
    }
    return arr;
}

@end

NS_ASSUME_NONNULL_END
