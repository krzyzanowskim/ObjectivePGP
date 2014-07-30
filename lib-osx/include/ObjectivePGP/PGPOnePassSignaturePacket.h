//
//  PGPOnePassSignaturePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 29/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@class PGPKeyID;

@interface PGPOnePassSignaturePacket : PGPPacket
@property (assign) UInt8 version; //  The current version is 3.
@property (assign) PGPSignatureType signatureType;
@property (assign) PGPHashAlgorithm hashAlgorith;
@property (assign) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign) PGPKeyID *keyID; // 8
@property (assign) BOOL notNested;
@end
