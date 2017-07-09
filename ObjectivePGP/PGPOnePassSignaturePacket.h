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

@property (nonatomic) UInt8 version; //  The current version is 3.
@property (nonatomic) PGPSignatureType signatureType;
@property (nonatomic) PGPHashAlgorithm hashAlgorith;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic) PGPKeyID *keyID; // 8
@property (nonatomic) BOOL notNested;

@end
