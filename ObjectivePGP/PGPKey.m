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
#import "PGPSecretSubKeyPacket.m"
#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"
#import "PGPSubKey.h"

@implementation PGPKey

- (instancetype) initWithPackets:(NSArray *)packets
{
    if (self = [self init]) {
        [self loadPackets:packets];
    }
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ primary key: %@",[super description], self.primaryKeyPacket];
}

- (NSMutableArray *)users
{
    if (!_users) {
        _users = [NSMutableArray array];
    }
    return _users;
}

- (NSMutableArray *)subKeys
{
    if (!_subKeys) {
        _subKeys = [NSMutableArray array];
    }
    return _subKeys;
}

- (NSMutableArray *)directSignatures
{
    if (!_directSignatures) {
        _directSignatures = [NSMutableArray array];
    }
    return _directSignatures;
}

- (BOOL)isEncrypted
{
    if (self.type == PGPKeySecret) {
        PGPSecretKeyPacket *secretPacket = (PGPSecretKeyPacket *)self.primaryKeyPacket;
        return secretPacket.isEncrypted;
    }
    return NO;
}

- (PGPKeyType)type
{
    PGPKeyType t = PGPKeyUnknown;

    switch (self.primaryKeyPacket.tag) {
        case PGPPublicKeyPacketTag:
            t = PGPKeyPublic;
            break;
        case PGPSecretKeyPacketTag:
            t = PGPKeySecret;
        default:
            break;
    }

    return t;
}

- (void) loadPackets:(NSArray *)packets
{
    // based on packetlist2structure
    PGPKeyID *primaryKeyID = nil;
    PGPSubKey *subKey      = nil;
    PGPUser *user          = nil;

    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPPublicKeyPacketTag:
                primaryKeyID = [(PGPPublicKeyPacket *)packet keyID];
                self.primaryKeyPacket = packet;
                break;
            case PGPSecretKeyPacketTag:
                primaryKeyID = [(PGPSecretKeyPacket *)packet keyID];
                self.primaryKeyPacket = packet;
                break;
            case PGPUserAttributePacketTag:
                if (!user) {
                    continue;
                }
                user.userAttribute = (PGPUserAttributePacket *)packet;
                break;
            case PGPUserIDPacketTag:
                if (!user) {
                    user = [[PGPUser alloc] initWithPacket:(PGPUserIDPacket *)packet];
                }
                [self.users addObject:user];
                break;
            case PGPPublicSubkeyPacketTag:
            case PGPSecretSubkeyPacketTag:
                user = nil;
                subKey = [[PGPSubKey alloc] initWithPacket:packet];
                [self.subKeys addObject:subKey];
                break;
            case PGPSignaturePacketTag:
            {
                PGPSignaturePacket *signaturePacket = (PGPSignaturePacket *)packet;
                switch (signaturePacket.type) {
                    case PGPSignatureGenericCertificationUserIDandPublicKey:
                    case PGPSignatureCasualCertificationUserIDandPublicKey:
                    case PGPSignaturePositiveCertificationUserIDandPublicKey:
                    case PGPSignaturePersonalCertificationUserIDandPublicKey:
                        if (!user) {
                            continue;
                        }
                        if ([signaturePacket.issuerKeyID isEqual:primaryKeyID]) {
                            user.selfSignatures = [user.selfSignatures arrayByAddingObject:packet];
                        } else {
                            user.otherSignatures = [user.otherSignatures arrayByAddingObject:packet];
                        }
                        break;
                    case PGPSignatureCertificationRevocation:
                        if (user) {
                            user.revocationSignatures = [user.revocationSignatures arrayByAddingObject:packet];
                        } else {
                            [self.directSignatures addObject:packet];
                        }
                        break;
                    case PGPSignatureDirectlyOnKey:
                        [self.directSignatures addObject:packet];
                        break;
                    case PGPSignatureSubkeyBinding:
                        if (!subKey) {
                            continue;
                        }
                        subKey.bindingSignature = (PGPSignaturePacket *)packet;
                        break;
                    case PGPSignatureKeyRevocation:
                        self.revocationSignature = (PGPSignaturePacket *)packet;
                        break;
                    case PGPSignatureSubkeyRevocation:
                        if (!subKey) {
                            continue;
                        }
                        subKey.revocationSignature = (PGPSignaturePacket *)packet;
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
- (PGPPacket *) signingKeyPacket
{
    NSAssert(self.type == PGPKeySecret, @"Need secret key to sign");
    if (self.type == PGPKeyPublic) {
        NSLog(@"Need secret key to sign");
        return nil;
    }

    for (PGPUser *user in self.users) {
        for (PGPSignaturePacket *selfSignature in user.selfSignatures) {
            if (selfSignature.canBeUsedToSign) {
                return self.primaryKeyPacket;
            }
        }
    }

    for (PGPSignaturePacket *signaturePacket in self.directSignatures) {
        if (signaturePacket.canBeUsedToSign) {
            return self.primaryKeyPacket;
        }
    }

    for (PGPSubKey *subKey in self.subKeys) {
        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
        if (signaturePacket.canBeUsedToSign) {
            return subKey.keyPacket;
        }
    }

    return nil;
}

//- (PGPSignaturePacket *) signingSignature
//{
//    for (PGPUser *user in self.users) {
//        for (PGPSignaturePacket *selfSignature in user.selfSignatures) {
//            if (selfSignature.canBeUsedToSign) {
//                return selfSignature;
//            }
//        }
//    }
//
//    for (PGPSignaturePacket *signaturePacket in self.directSignatures) {
//        if (signaturePacket.canBeUsedToSign) {
//            return signaturePacket;
//        }
//    }
//
//    for (PGPSubKey *subKey in self.subKeys) {
//        PGPSignaturePacket *signaturePacket = subKey.bindingSignature;
//        if (signaturePacket.canBeUsedToSign) {
//            return signaturePacket;
//        }
//    }
//
//    return nil;
//}

- (BOOL) decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error
{
    BOOL ret = NO;
    for (PGPPacket * packet in [self allKeyPackets]) {
        if (packet.tag == PGPSecretKeyPacketTag) {
            PGPSecretKeyPacket *secretKeyPacket = (PGPSecretKeyPacket *)packet;
            ret = [secretKeyPacket decrypt:passphrase error:error];
        } else if (packet.tag == PGPSecretSubkeyPacketTag) {
            PGPSecretSubKeyPacket *secretSubKeyPacket = (PGPSecretSubKeyPacket *)packet;
            ret = [secretSubKeyPacket decrypt:passphrase error:error];
        }
    }
    return ret;
}

- (NSData *) export:(NSError *__autoreleasing *)error
{
    NSMutableData *result = [NSMutableData data];

    for (PGPPacket * packet in [self allPackets]) {
        NSError *error = nil;
        [result appendData:[packet exportPacket:&error]];
        NSAssert(!error,@"Error while export public key");

        //TODO: append checksum?
    }
    return [result copy];
}

#pragma mark - Private

/**
 *  Ordered list of packets. Trust Packet is not exported.
 *
 *  @return array
 */
- (NSArray *)allPackets
{
    //TODO: handle trust packet somehow. The Trust packet is used only within keyrings and is not normally exported.
    NSMutableArray *arr = [NSMutableArray array];

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

    return [arr copy];
}

- (NSArray *)allKeyPackets
{
    NSMutableArray *arr = [NSMutableArray arrayWithObject:self.primaryKeyPacket];
    for (PGPSubKey *subKey in self.subKeys) {
        [arr addObject:subKey.keyPacket];
    }
    return [arr copy];
}

@end
