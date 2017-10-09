//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPublicKeyPacket.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPS2K;

@interface PGPSecretKeyPacket : PGPPublicKeyPacket <NSCopying, PGPExportable>

@property (nonatomic, readonly) PGPS2KUsage s2kUsage;
@property (nonatomic, copy, readonly) PGPS2K *s2k;
@property (nonatomic, readonly) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic, nullable, copy, readonly) NSData *ivData;
@property (nonatomic, getter=isEncryptedWithPassphrase, readonly) BOOL encryptedWithPassphrase;

/**
 *  Decrypt packet
 *
 *  @param passphrase Passphrase
 *  @param error      error
 *
 *  @return Decrypted key on success
 */
- (nullable PGPSecretKeyPacket *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError *__autoreleasing _Nullable *)error;

- (nullable PGPMPI *)secretMPI:(NSString *)identifier;

@end

NS_ASSUME_NONNULL_END
