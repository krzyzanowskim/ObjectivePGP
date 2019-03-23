//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPUser.h"
#import "PGPUser+Private.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeImageSubpacket.h"
#import "PGPUserIDPacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"
#import "NSArray+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPUser

@synthesize userIDPacket = _userIDPacket;

- (instancetype)initWithUserIDPacket:(PGPUserIDPacket *)userPacket {
    PGPAssertClass(userPacket, PGPUserIDPacket);

    if (self = [super init]) {
        _userIDPacket = [userPacket copy];
        _otherSignatures = [NSArray<PGPSignaturePacket *> array];
        _revocationSignatures = [NSArray<PGPSignaturePacket *> array];
        _selfCertifications = [NSArray<PGPSignaturePacket *> array];
    }
    return self;
}

- (NSString *)userID {
    return self.userIDPacket.userID;
}

- (nullable NSData *)image {
    // find image uset attribute
    let imageAttributeSubpacket = PGPCast([[self.userAttribute.subpackets pgp_objectsPassingTest:^BOOL(PGPUserAttributeSubpacket * _Nonnull subpacket, BOOL * _Nonnull stop) {
        BOOL found = subpacket.type == PGPUserAttributeSubpacketImage;
        *stop = found;
        return found;
    }] firstObject], PGPUserAttributeImageSubpacket);

    return imageAttributeSubpacket.image;
}

- (void)setImage:(nullable NSData *)image {
    // Replace image subpacket
    if (!self.userAttribute) {
        self.userAttribute = [[PGPUserAttributePacket alloc] init];
    }

    NSMutableArray<PGPUserAttributeSubpacket *> *subpackets = [self.userAttribute.subpackets mutableCopy];
    let imageSubpacketIndex = [subpackets indexOfObjectPassingTest:^BOOL(PGPUserAttributeSubpacket * _Nonnull subpacket, NSUInteger __unused idx, BOOL * _Nonnull stop) {
        BOOL found = subpacket.type == PGPUserAttributeSubpacketImage;
        *stop = found;
        return found;
    }];

    if (imageSubpacketIndex != NSNotFound) {
        [subpackets removeObjectAtIndex:imageSubpacketIndex];
    }

    let imageSubpacket = [PGPUserAttributeImageSubpacket new];
    imageSubpacket.type = PGPUserAttributeSubpacketImage;
    imageSubpacket.image = image;

    [subpackets addObject:imageSubpacket];
    self.userAttribute.subpackets = [subpackets copy];
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", [super description], self.userID];
}

- (NSArray<PGPPacket *> *)allPackets {
    let arr = [NSMutableArray<PGPPacket *> array];

    [arr pgp_addObject:self.userIDPacket];
    [arr pgp_addObject:self.userAttribute];

    for (id packet in self.revocationSignatures) {
        [arr addObject:packet];
    }

    for (id packet in self.selfCertifications) {
        [arr addObject:packet];
    }

    for (id packet in self.otherSignatures) {
        [arr addObject:packet];
    }

    return arr;
}

// Returns the most recent self-signature of the user.
// Including expired certificates
- (nullable PGPSignaturePacket *)latestSelfCertificate {
    if (self.selfCertifications.count == 0) {
        return nil;
    }

    NSMutableArray *certs = [NSMutableArray array];
    for (PGPSignaturePacket *signature in self.selfCertifications) {
        // TODO: check for revocation

        [certs addObject:signature];
        // This only worked as verify wasn't implemented correctly
        // TODO: find a better solution
        //
        //        // (this is the craziest thing I ever seen today)
        //        NSError *error;
        //        [signature verifyData:nil withKey:key signingKeyPacket:(PGPPublicKeyPacket *)key.primaryKeyPacket userID:self.userID error:&error];
        //        //BOOL status = [signature verifyData:nil withKey:key signingKeyPacket:(PGPPublicKeyPacket *)key.primaryKeyPacket userID:self.userID error:&error];
        //        //if (!status) {
        //        //    NSLog(@"ObjectivePGP: %@",error);
        //        //}
        //        //NSAssert(status == YES,@"not verified");
        //
        //        if (status == YES) {
        //            [certs addObject:signature];
        //        }
    }

    [certs sortUsingComparator:^NSComparisonResult(id obj1, id obj2) {
        let sig1 = PGPCast(obj1, PGPSignaturePacket);
        let sig2 = PGPCast(obj2, PGPSignaturePacket);
        if (sig1.creationDate && sig2.creationDate) {
            return [PGPNN(sig1.creationDate) compare:PGPNN(sig2.creationDate)];
        }
        return NSOrderedSame;
    }];

    return [certs firstObject];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToUser:other];
    }
    return NO;
}

- (BOOL)isEqualToUser:(PGPUser *)other {
    return PGPEqualObjects(self.userID,other.userID) &&
           PGPEqualObjects(self.userAttribute,other.userAttribute) &&
           PGPEqualObjects(self.selfCertifications,other.selfCertifications) &&
           PGPEqualObjects(self.otherSignatures,other.otherSignatures) &&
           PGPEqualObjects(self.revocationSignatures,other.revocationSignatures) &&
           PGPEqualObjects(self.userIDPacket,other.userIDPacket);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + self.userID.hash;
    result = prime * result + self.userAttribute.hash;
    result = prime * result + self.selfCertifications.hash;
    result = prime * result + self.otherSignatures.hash;
    result = prime * result + self.revocationSignatures.hash;
    result = prime * result + self.userIDPacket.hash;

    return result;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let user = PGPCast([[self.class allocWithZone:zone] initWithUserIDPacket:self.userIDPacket], PGPUser);
    user.userAttribute = self.userAttribute;
    user.selfCertifications = [[NSArray alloc] initWithArray:self.selfCertifications copyItems:YES];
    user.otherSignatures = [[NSArray alloc] initWithArray:self.otherSignatures copyItems:YES];
    user.revocationSignatures = [[NSArray alloc] initWithArray:self.revocationSignatures copyItems:YES];
    return user;
}

@end

NS_ASSUME_NONNULL_END
