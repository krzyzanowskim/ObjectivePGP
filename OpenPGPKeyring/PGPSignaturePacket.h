//
//  PGPSignature.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 2

#import <Foundation/Foundation.h>
#import "PGPPacketFactory.h"

@interface PGPSignaturePacket : PGPPacket <PGPPacket>

@property (assign, readonly) UInt8 version;
@property (assign, readonly) PGPSignatureType signatureType;
@property (assign, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign, readonly) PGPHashAlgorithm hashAlgoritm;
@property (strong, readonly, nonatomic) NSMutableArray *hashedSubpackets;
@property (strong, readonly, nonatomic) NSMutableArray *unhashedSubpackets;

@end
