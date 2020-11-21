//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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
@property (nonatomic, readonly) PGPSignatureType type;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgoritm;
@property (nonatomic, copy, readonly) NSArray<PGPSignatureSubpacket *> *hashedSubpackets;
@property (nonatomic, copy, readonly) NSArray<PGPSignatureSubpacket *> *unhashedSubpackets;
/// Two-octet field holding the left 16 bits of the signed hash value.
/// Read from the key or set byt the call to `-[PGPSignaturePacket signData:usingKey:passphrase:userID:error]`
@property (nonatomic, copy, nullable) NSData *signedHashValueData;
@property (nonatomic, copy) NSArray<PGPMPI *> *signatureMPIs;

@property (nonatomic, readonly) BOOL canBeUsedToSign; // computed
@property (nonatomic, readonly) BOOL canBeUsedToEncrypt; // computed

@property (nonatomic, nullable, readonly) PGPKeyID *issuerKeyID; // computed
@property (nonatomic, copy, readonly) NSArray<PGPSignatureSubpacket *> *subpackets; // computed
@property (nonatomic, nullable, readonly) NSDate *expirationDate; // computed
/// Key expiration time interval. To be calculated since key creation date. NSNotFound if not specified.
@property (nonatomic, assign, readonly) NSTimeInterval keyExpirationTimeInterval; // computed
@property (nonatomic, readonly, readonly, getter=isExpired) BOOL expired; // computed
@property (nonatomic, nullable, readonly) NSDate *creationDate; // computed
@property (nonatomic, readonly, readonly, getter=isPrimaryUserID) BOOL primaryUserID; // computed

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
- (NSData *)calculateSignedHashForDataToSign:(NSData *)dataToSign;

/**
 *  Build signature data (signature packet with subpackets).
 *
 *  @param inputData Data to sign.
 *  @param key   A key used to create signature.
 *  @param subKey Optional. if signature subkey can't be found automatically.
 *  @param passphrase Optional. Key passphrase do decrypt.
 *  @param userID Optional.
 *  @param error     error
 *
 *  @return YES on success.
 */
- (BOOL)signData:(nullable NSData *)inputData withKey:(PGPKey *)key subKey:(nullable PGPKey *)subKey passphrase:(nullable NSString *)passphrase userID:(nullable NSString *)userID error:(NSError * __autoreleasing *)error;

- (BOOL)verifyData:(NSData *)inputData publicKey:(PGPKey *)publicKey error:(NSError * __autoreleasing _Nullable *)error;
- (BOOL)verifyData:(NSData *)inputData publicKey:(PGPKey *)publicKey userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error;
- (BOOL)verifyData:(NSData *)inputData publicKey:(PGPKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(nullable NSString *)userID error:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
