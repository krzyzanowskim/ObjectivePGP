//
//  PGPKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"
#import "PGPPartialKey.h"
#import "PGPTypes.h"

#import "PGPExportableProtocol.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Public + Private key with the same ID.
@interface PGPKey : NSObject <PGPExportable>

PGP_EMPTY_INIT_UNAVAILABLE;

/// Key ID
@property (nonatomic, readonly) PGPKeyID *keyID;
@property (nonatomic, nullable, readonly) PGPPartialKey *secretKey;
@property (nonatomic, nullable, readonly) PGPPartialKey *publicKey;
@property (nonatomic, nullable, readonly) NSDate *expirationDate;

/// Whether key is secret.
@property (nonatomic, readonly) BOOL isSecret;
/// Whether key is public.
@property (nonatomic, readonly) BOOL isPublic;
/// Whether key is encrypted
@property (nonatomic, readonly) BOOL isEncryptedWithPassword;

@property (nonatomic, nullable, readonly) PGPSecretKeyPacket *signingSecretKey;

- (instancetype)initWithSecretKey:(nullable PGPPartialKey *)secretKey publicKey:(nullable PGPPartialKey *)publicKey NS_DESIGNATED_INITIALIZER;

/// The binary format.
/// @discussion If you need ASCII format, you can use `PGPArmor`.
- (nullable NSData *)export:(PGPPartialKeyType)keyType error:(NSError *__autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
