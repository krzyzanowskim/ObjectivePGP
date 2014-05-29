//
//  PGPUser.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@class PGPUserIDPacket, PGPUserAttributePacket, PGPSignaturePacket, PGPKey;

@interface PGPUser : NSObject
@property (strong, nonatomic) NSString *userID;
@property (strong, nonatomic) PGPUserAttributePacket *userAttribute;
@property (strong, nonatomic) NSArray *selfCertifications;
@property (strong, nonatomic) NSArray *otherSignatures;
@property (strong, nonatomic) NSArray *revocationSignatures;

@property (strong, nonatomic) PGPUserIDPacket *userIDPacket;

- (instancetype) initWithUserIDPacket:(PGPUserIDPacket *)userPacket;
- (NSArray *) allPackets;
- (PGPSignaturePacket *) validSelfCertificate:(PGPKey *)key;


@end
