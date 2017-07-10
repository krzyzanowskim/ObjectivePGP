//
//  PGPSignature.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 2

#import "PGPKeyID.h"
#import "PGPMPI.h"
#import "PGPPacketFactory.h"
#import "PGPSignatureSubpacket.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPPartialKey, PGPUser, PGPUserIDPacket, PGPPublicKeyPacket, PGPKey;

@interface PGPSignaturePacket : PGPPacket <NSCopying>

@property (nonatomic) UInt8 version;
@property (nonatomic) PGPSignatureType type;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgoritm;
@property (nonatomic, copy, readonly) NSArray<PGPSignatureSubpacket *> *hashedSubpackets;
@property (nonatomic, copy, readonly) NSArray<PGPSignatureSubpacket *> *unhashedSubpackets;
@property (nonatomic) NSData *signedHashValueData;
@property (nonatomic, copy) NSArray<PGPMPI *> *signatureMPIs;

@property (nonatomic, readonly) BOOL canBeUsedToSign; // computed
@property (nonatomic, readonly) BOOL canBeUsedToEncrypt; // computed

@property (nonatomic, nullable, readonly) PGPKeyID *issuerKeyID;
@property (nonatomic, copy, readonly) NSArray<PGPSignatureSubpacket *> *subpackets;
@property (nonatomic, nullable, readonly) NSDate *expirationDate; // computed
@property (nonatomic, readonly, readonly) BOOL isExpired; // computed
@property (nonatomic, nullable, readonly) NSDate *creationDate; // computed
@property (nonatomic, readonly, readonly) BOOL isPrimaryUserID; // computed

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
- (BOOL)signData:(NSData *)inputData secretKey:(PGPPartialKey *)secretKey error:(NSError *__autoreleasing *)error DEPRECATED_ATTRIBUTE;
- (BOOL)signData:(NSData *)inputData usingKey:(PGPKey *)key passphrase:(nullable NSString *)passphrase userID:(nullable NSString *)userID error:(NSError *__autoreleasing *)error;

- (BOOL)verifyData:(NSData *)inputData withKey:(PGPPartialKey *)publicKey error:(NSError *__autoreleasing *)error;
- (BOOL)verifyData:(NSData *)inputData withKey:(PGPPartialKey *)publicKey userID:(nullable NSString *)userID error:(NSError *__autoreleasing *)error;
- (BOOL)verifyData:(NSData *)inputData withKey:(PGPPartialKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(nullable NSString *)userID error:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
