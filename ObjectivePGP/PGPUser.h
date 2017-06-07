//
//  PGPUser.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPUserIDPacket, PGPUserAttributePacket, PGPSignaturePacket, PGPKey;

@interface PGPUser : NSObject

@property (nonatomic, copy) NSString *userID;
@property (nonatomic) PGPUserAttributePacket *userAttribute;
@property (nonatomic) NSArray<PGPSignaturePacket *> *selfCertifications;
@property (nonatomic) NSArray<PGPSignaturePacket *> *otherSignatures;
@property (nonatomic) NSArray<PGPSignaturePacket *> *revocationSignatures;

@property (nonatomic) PGPUserIDPacket *userIDPacket;
@property (nonatomic) NSArray<PGPPacket *> *allPackets;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithUserIDPacket:(PGPUserIDPacket *)userPacket NS_DESIGNATED_INITIALIZER;
- (nullable PGPSignaturePacket *)validSelfCertificate:(PGPKey *)key;

@end

NS_ASSUME_NONNULL_END
