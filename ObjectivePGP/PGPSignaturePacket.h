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
#import "PGPSignatureSubpacket.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPKey, PGPUser, PGPUserIDPacket, PGPPublicKeyPacket, PGPCompoundKey;

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

@property (nonatomic, readonly) PGPKeyID *issuerKeyID;
@property (nonatomic, copy, readonly) NSArray<PGPPacket *> *subpackets;
@property (nonatomic, nullable) NSDate *expirationDate;
@property (nonatomic, readonly) BOOL isExpired;
@property (nonatomic, nullable) NSDate *creationDate;
@property (nonatomic, readonly) BOOL isPrimaryUserID;

/**
 *  Create signature packet for signing. This is convienience constructor.
 *
 *  @param type               example: PGPSignatureBinaryDocument
 *  @param hashAlgorithm      hash algorithm to be used for signature
 *
 *  @return Packet instance ready to call signData:secretKey
 */
+ (PGPSignaturePacket *)signaturePacket:(PGPSignatureType)type hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

- (NSArray<PGPSignatureSubpacket *> *)subpacketsOfType:(PGPSignatureSubpacketType)type;

/**
 *  Build signature data (signature packet with subpackets).
 *
 *  @param inputData Data to sign
 *  @param secretKey Secret key used to create signature
 *  @param error     error
 *
 *  @return YES on success.
 */
- (BOOL)signData:(NSData *)inputData secretKey:(PGPKey *)secretKey error:(NSError * __autoreleasing *)error DEPRECATED_ATTRIBUTE;
- (BOOL)signData:(NSData *)inputData usingKey:(PGPCompoundKey *)key passphrase:(nullable NSString *)passphrase userID:(nullable NSString *)userID error:(NSError * __autoreleasing *)error;

- (BOOL)verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey error:(NSError * __autoreleasing *)error;
- (BOOL)verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey userID:(nullable NSString *)userID error:(NSError * __autoreleasing *)error;
- (BOOL)verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(nullable NSString *)userID error:(NSError * __autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
