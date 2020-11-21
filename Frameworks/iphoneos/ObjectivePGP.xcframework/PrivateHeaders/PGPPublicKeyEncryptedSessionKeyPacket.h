//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"
#import "PGPExportableProtocol.h"
#import "PGPEncryptedSessionKeyPacketProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPKeyID, PGPPublicKeyPacket, PGPSecretKeyPacket;

@interface PGPPublicKeyEncryptedSessionKeyPacket : PGPPacket <PGPEncryptedSessionKeyPacketProtocol, NSCopying, PGPExportable>
@property (nonatomic) UInt8 version;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, copy) PGPKeyID *keyID;

- (BOOL)encrypt:(PGPPublicKeyPacket *)publicKeyPacket sessionKeyData:(NSData *)sessionKeyData sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm error:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)decryptSessionKeyData:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm *)sessionKeyAlgorithm error:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
