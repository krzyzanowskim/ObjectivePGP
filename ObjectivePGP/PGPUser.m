//
//  PGPUser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUser.h"
#import "PGPSignaturePacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPUserIDPacket.h"
#import "PGPKey.h"
#import "PGPUserAttributePacket.h"

@implementation PGPUser

- (instancetype) initWithUserIDPacket:(PGPUserIDPacket *)userPacket
{
    if (self = [self init]) {
        _userIDPacket = userPacket;
    }
    return self;
}

- (NSString *)userID
{
    return self.userIDPacket.userID;
}

- (NSUInteger)hash
{
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + [_userID hash];
    result = prime * result + [_userAttribute hash];
    result = prime * result + [_selfCertifications hash];
    result = prime * result + [_otherSignatures hash];
    result = prime * result + [_revocationSignatures hash];
    result = prime * result + [_userIDPacket hash];

    return result;
}

- (NSArray *)otherSignatures
{
    if (!_otherSignatures) {
        _otherSignatures = [NSArray array];
    }
    return _otherSignatures;
}

- (NSArray *)revocationSignatures
{
    if (!_revocationSignatures) {
        _revocationSignatures = [NSArray array];
    }
    return _revocationSignatures;
}

- (NSArray *)selfCertifications
{
    if (!_selfCertifications) {
        _selfCertifications = [NSArray array];
    }
    return _selfCertifications;
}

- (PGPUserIDPacket *)userIDPacket
{
    if (!_userIDPacket) {
        NSAssert(false, @"wat?");
        // build userIDPacket
    }
    return _userIDPacket;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@",[super description], self.userID];
}

- (NSArray *) allPackets
{
    NSMutableArray *arr = [NSMutableArray array];

    if (self.userIDPacket) {
        [arr addObject:self.userIDPacket]; //TODO: || [arr addObject:self.userAttribute]
    }

    for (id packet in self.revocationSignatures) {
        [arr addObject:packet];
    }

    for (id packet in self.selfCertifications) {
        [arr addObject:packet];
    }

    for (id packet in self.otherSignatures) {
        [arr addObject:packet];
    }

    return [arr copy];
}

//TODO:
//User.prototype.getValidSelfCertificate = function(primaryKey) {
//    if (!this.selfCertifications) {
//        return null;
//    }
//    var validCert = [];
//    for (var i = 0; i < this.selfCertifications.length; i++) {
//        if (this.isRevoked(this.selfCertifications[i], primaryKey)) {
//            continue;
//        }
//        if (!this.selfCertifications[i].isExpired() &&
//            (this.selfCertifications[i].verified ||
//             this.selfCertifications[i].verify(primaryKey, {userid: this.userId || this.userAttribute, key: primaryKey}))) {
//                validCert.push(this.selfCertifications[i]);
//            }
//    }
//    // most recent first
//    validCert = validCert.sort(function(a, b) {
//        a = a.created;
//        b = b.created;
//        return a>b ? -1 : a<b ? 1 : 0;
//    });
//    return validCert[0];
//};

// Returns the most significant (latest valid) self signature of the user
- (PGPSignaturePacket *) validSelfCertificate:(PGPKey *)key
{
    if (self.selfCertifications.count == 0) {
        return nil;
    }

    NSMutableArray *certs = [NSMutableArray array];
    for (PGPSignaturePacket *signature in self.selfCertifications) {
        //TODO: check for revocation

        if (signature.isExpired) {
            continue;
        }
        [certs addObject:signature];
        // This only worked as verify wasn't implemented correctly
        // TODO: find a better solution
        //
        //        // (this is craziest think I ever seen today)
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
        PGPSignaturePacket *sig1 = obj1;
        PGPSignaturePacket *sig2 = obj2;
        return [sig1.creationDate compare:sig2.creationDate];
    }];

    return [certs firstObject];
}

@end
