//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPExportableProtocol.h"
#import "PGPKeyID.h"
#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, PGPKeyType) {
    PGPKeyTypeUnknown = 0,
    PGPKeyTypeSecret = 1,
    PGPKeyTypePublic = 2
};

@class PGPPacket, PGPSignaturePacket, PGPUser, PGPSecretKeyPacket, PGPPartialSubKey;

/// Single Private or Public key.
NS_SWIFT_NAME(PartialKey) @interface PGPPartialKey : NSObject <PGPExportable, NSCopying>

@property (nonatomic, readonly) PGPKeyType type;
@property (nonatomic, copy) PGPPacket *primaryKeyPacket;
@property (nonatomic, copy) NSArray<PGPUser *> *users;
@property (nonatomic, copy, readonly) NSArray<PGPPartialSubKey *> *subKeys;
@property (nonatomic, copy, readonly) NSArray<PGPSignaturePacket *> *directSignatures;
@property (nonatomic, nullable, copy, readonly) PGPSignaturePacket *revocationSignature;

@property (nonatomic, readonly) BOOL isEncryptedWithPassword; // calculated
@property (nonatomic, nullable, readonly) NSDate *expirationDate; // calculated
@property (nonatomic, readonly) PGPKeyID *keyID; // calculated
@property (nonatomic, readonly) PGPFingerprint *fingerprint; // calculated

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets NS_DESIGNATED_INITIALIZER;

/**
 *  Decrypts all secret key and subkey packets
 *  Warning: It is not good idea to keep decrypted key around
 *
 *  @param passphrase Passphrase
 *  @param error      error
 *
 *  @return Decrypted key, or `nil`.
 */
- (nullable PGPPartialKey *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error;

/**
 *  Signing key packet
 *
 *  @return PGPSecureKeyPacket that can be used to signing
 */
@property (nonatomic, nullable, readonly) PGPPacket *signingKeyPacket;

- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID;
- (nullable PGPPacket *)encryptionKeyPacket:(NSError * __autoreleasing *)error;
- (nullable PGPSecretKeyPacket *)decryptionPacketForKeyID:(PGPKeyID *)keyID error:(NSError * __autoreleasing *)error;

- (NSArray<PGPPacket *> *)allKeyPackets;
- (PGPSymmetricAlgorithm)preferredSymmetricAlgorithm;
+ (PGPSymmetricAlgorithm)preferredSymmetricAlgorithmForKeys:(NSArray<PGPPartialKey *> *)keys;

-(instancetype)copyWithZone:(nullable NSZone *)zone NS_REQUIRES_SUPER;

@end

NS_ASSUME_NONNULL_END
