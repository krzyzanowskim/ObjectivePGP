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

@class PGPKey, PGPUser, PGPUserIDPacket, PGPPublicKeyPacket;

@interface PGPSignaturePacket : PGPPacket <NSCopying>

@property (nonatomic) UInt8 version;
@property (nonatomic) PGPSignatureType type;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgoritm;
@property (nonatomic, readonly) NSArray *hashedSubpackets;
@property (nonatomic, readonly) NSArray *unhashedSubpackets;
@property (nonatomic) NSData *signedHashValueData;
@property (nonatomic) NSArray *signatureMPIs;

@property (nonatomic, readonly) BOOL canBeUsedToSign;
@property (nonatomic, readonly) BOOL canBeUsedToEncrypt;

/**
 *  Create signature packet for signing. This is convienience constructor.
 *
 *  @param type               example: PGPSignatureBinaryDocument
 *  @param hashAlgorithm      hash algorithm to be used for signature
 *
 *  @return Packet instance ready to call signData:secretKey
 */
+ (PGPSignaturePacket *) signaturePacket:(PGPSignatureType)type hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

- (PGPKeyID *) issuerKeyID;
- (NSArray *) subpackets;
- (NSArray *) subpacketsOfType:(PGPSignatureSubpacketType)type;
- (NSDate *) expirationDate;
- (BOOL) isExpired;
- (NSDate *) creationDate;
- (BOOL) isPrimaryUserID;


/**
 *  Build signature data (signature packet with subpackets).
 *
 *  @param secretKey Secret key used to create signature
 *  @param inputData Data to sign
 *  @param error     error
 *
 *  @return Signature packet data
 */
- (BOOL) signData:(NSData *)inputData secretKey:(PGPKey *)secretKey error:(NSError * __autoreleasing *)error;
- (BOOL) signData:(NSData *)inputData secretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase userID:(NSString *)userID error:(NSError * __autoreleasing *)error;


- (BOOL) verifyData:(NSData *)inputData  withKey:(PGPKey *)publicKey error:(NSError * __autoreleasing *)error;
- (BOOL) verifyData:(NSData *)inputData  withKey:(PGPKey *)publicKey userID:(NSString *)userID error:(NSError * __autoreleasing *)error;
- (BOOL) verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(NSString *)userID error:(NSError * __autoreleasing *)error;


@end
