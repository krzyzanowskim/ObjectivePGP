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

@class PGPKey, PGPUser;

@interface PGPSignaturePacket : PGPPacket

@property (assign, readonly) UInt8 version;
@property (assign, readonly) PGPSignatureType type;
@property (assign, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign, readonly) PGPHashAlgorithm hashAlgoritm;
@property (strong, readonly, nonatomic) NSMutableArray *hashedSubpackets;
@property (strong, readonly, nonatomic) NSMutableArray *unhashedSubpackets;
@property (strong) NSArray *signatureMPIs;

@property (assign, nonatomic, readonly) BOOL canBeUsedToSign;

// A V4 signature hashes the packet body
// starting from its first field, the version number, through the end
// of the hashed subpacket data.  Thus, the fields hashed are the
// signature version, the signature type, the public-key algorithm, the
// hash algorithm, the hashed subpacket length, and the hashed
// subpacket body.
@property (strong) NSData *signedPartData;
//@property (strong) NSData *signature;

// Two-octet field holding left 16 bits of signed hash value. (not signatureData, but full data
// The concatenation of the data being signed and the
// !!! signature data from the version number through the hashed subpacket data (inclusive) is hashed. !!!
// The resulting hash value is what is signed.
@property (strong) NSData *signedHashValueData; // BE


// Issuer key id
- (PGPKeyID *) issuerKeyID;
// All subpackets
- (NSArray *) subpackets;
// sign
- (NSData *) sign:(PGPKey *)secretKey user:(PGPUser *)user;


@end
