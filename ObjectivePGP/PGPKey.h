//
//  PGPKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPublicKeyPacket.h"
#import "PGPSignaturePacket.h"

@interface PGPKey : NSObject
@property (strong) PGPPublicKeyPacket *publicKeyPacket;
@property (strong) NSArray *revocationSignatures; //Zero or more revocation PGPSignaturePacket
@property (strong) NSArray *userIDPackets; //One or more User ID packets
//After each User ID packet, zero or more Signature packets (certifications)
//Zero or more User Attribute packets
//After each User Attribute packet, zero or more Signature packets (certifications)
@property (strong) NSArray *subkeys; //Zero or more PGPSubKey
//After each Subkey packet, one Signature packet, plus optionally a revocation
@end
