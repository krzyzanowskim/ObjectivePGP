//
//  PGPSignature.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 2

#import <Foundation/Foundation.h>
#import "PGPPacketFactory.h"
#import "PGPKeyID.h"

@interface PGPSignaturePacket : PGPPacket <PGPPacket>

@property (assign, readonly) UInt8 version;
@property (assign, readonly) PGPSignatureType type;
@property (assign, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign, readonly) PGPHashAlgorithm hashAlgoritm;
@property (strong, readonly, nonatomic) NSMutableArray *hashedSubpackets;
@property (strong, readonly, nonatomic) NSMutableArray *unhashedSubpackets;

@property (strong) NSData *signedData;
@property (strong) NSArray *signatureMPIs;

/**
 *  Issuer key id
 *
 *  @return PGPKeyID
 */
- (PGPKeyID *) issuerKeyID;

/**
 *  All subpackets;
 *
 *  @return Array of subpackets
 */
- (NSArray *) subpackets;

@end
