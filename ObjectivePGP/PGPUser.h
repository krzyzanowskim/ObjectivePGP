//
//  PGPUser.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPPacket.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPUserIDPacket, PGPUserAttributePacket, PGPSignaturePacket, PGPPartialKey;

NS_SWIFT_NAME(User) @interface PGPUser : NSObject <NSCopying>

@property (nonatomic, copy) NSString *userID;
@property (nonatomic, copy) PGPUserAttributePacket *userAttribute;
@property (nonatomic, copy) NSArray<PGPSignaturePacket *> *selfCertifications;
@property (nonatomic, copy) NSArray<PGPSignaturePacket *> *otherSignatures;
@property (nonatomic, copy) NSArray<PGPSignaturePacket *> *revocationSignatures;

@property (nonatomic, readonly) PGPUserIDPacket *userIDPacket;
@property (nonatomic, readonly) NSArray<PGPPacket *> *allPackets;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithUserIDPacket:(PGPUserIDPacket *)userPacket NS_DESIGNATED_INITIALIZER;
- (nullable PGPSignaturePacket *)validSelfCertificate:(PGPPartialKey *)key;

@end

NS_ASSUME_NONNULL_END
