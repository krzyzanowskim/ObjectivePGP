//
//  PGPKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPublicKeyPacket.h"
#import "PGPKeyID.h"

@interface PGPKey : NSObject
@property (strong, readonly) PGPPublicKeyPacket *packet;
@property (strong) NSArray *revocationSignatures; //Zero or more revocation PGPSignaturePacket
@property (strong) NSArray *users; //One or more User ID
//After each User ID packet, zero or more Signature packets (certifications)
//Zero or more User Attribute packets
//After each User Attribute packet, zero or more Signature packets (certifications)
@property (strong) NSArray *subkeys; //Zero or more PGPSubKey
//After each Subkey packet, one Signature packet, plus optionally a revocation

- (instancetype)initWithPacket:(PGPPublicKeyPacket *)packet NS_DESIGNATED_INITIALIZER;
- (PGPKeyID *)keyID;
- (NSData *)fingerprint;

@end
