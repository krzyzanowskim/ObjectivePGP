//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPSecretKeyPacket;

@interface PGPSymmetricallyEncryptedIntegrityProtectedDataPacket : PGPSymmetricallyEncryptedDataPacket

@property (nonatomic, readonly) NSUInteger version;

- (BOOL)encrypt:(NSData *)literalPacketData symmetricAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData error:(NSError * __autoreleasing *)error;
- (NSArray<PGPPacket *> *)decryptWithSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData isIntegrityProtected:(nullable BOOL *)isIntegrityProtected error:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
