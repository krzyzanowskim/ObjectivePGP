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

@property (assign) UInt8 version;
@property (assign) PGPSignatureType type;
@property (assign) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign) PGPHashAlgorithm hashAlgoritm;
@property (strong, readonly, nonatomic) NSArray *hashedSubpackets;
@property (strong, readonly, nonatomic) NSArray *unhashedSubpackets;
@property (strong) NSData *signedHashValueData;
@property (strong) NSArray *signatureMPIs;

@property (assign, nonatomic, readonly) BOOL canBeUsedToSign;
@property (assign, nonatomic, readonly) BOOL canBeUsedToEncrypt;

/**
 *  Create signature packet for signing. This is convienience constructor.
 *
 *  @param type               example: PGPSignatureBinaryDocument
 *  @param publicKeyAlgorithm public key algorith to be used for signature
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
 *  @param userID    Optional. User ID
 *
 *  @return Signature packet data
 */
- (BOOL) signData:(NSData *)inputData  secretKey:(PGPKey *)secretKey error:(NSError * __autoreleasing *)error;
- (BOOL) signData:(NSData *)inputData secretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase userID:(NSString *)userID error:(NSError * __autoreleasing *)error;


- (BOOL) verifyData:(NSData *)inputData  withKey:(PGPKey *)publicKey error:(NSError * __autoreleasing *)error;
- (BOOL) verifyData:(NSData *)inputData  withKey:(PGPKey *)publicKey userID:(NSString *)userID error:(NSError * __autoreleasing *)error;
- (BOOL) verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(NSString *)userID error:(NSError * __autoreleasing *)error;


@end
