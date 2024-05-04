//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPartialKey.h"
#import "PGPTypes.h"

#import "PGPExportableProtocol.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Public + Private key with the same ID.
NS_SWIFT_NAME(Key) @interface PGPKey : NSObject <PGPExportable, NSCopying>

PGP_EMPTY_INIT_UNAVAILABLE;

/// Key ID
@property (nonatomic, readonly) PGPKeyID *keyID;
@property (nonatomic, nullable, copy, readonly) PGPPartialKey *secretKey;
@property (nonatomic, nullable, copy, readonly) PGPPartialKey *publicKey;
@property (nonatomic, nullable, readonly) NSDate *expirationDate;

/// Whether key is secret.
@property (nonatomic, readonly) BOOL isSecret;
/// Whether key is public.
@property (nonatomic, readonly) BOOL isPublic;
/// Whether key is encrypted
@property (nonatomic, readonly) BOOL isEncryptedWithPassword;

@property (nonatomic, nullable, readonly) PGPSecretKeyPacket *signingSecretKey;


/// Initialize the key with partial keys
- (instancetype)initWithSecretKey:(nullable PGPPartialKey *)secretKey publicKey:(nullable PGPPartialKey *)publicKey NS_DESIGNATED_INITIALIZER;

/**
*  Decrypts key.
*  Warning: It is not good idea to keep decrypted key around
*
*  @param passphrase Passphrase
*  @param error      error
*
*  @return Decrypted key, or `nil`.
*/
- (nullable PGPKey *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error;


/// The binary format.
/// @discussion If you need ASCII format, you can use `PGPArmor`.
- (nullable NSData *)export:(PGPKeyType)keyType error:(NSError * __autoreleasing _Nullable *)error NS_SWIFT_NAME(export(keyType:));

/**
*  Adds a UserId to both public and secret keys. The userid is self signed by the key
*
*  @param userId format generally name <email@address>
*  @param passphraseBlock Passphrase
*
*/
- (void)addUserId:(NSString*)userId
 passphraseForKey:(nullable NSString * _Nullable(^NS_NOESCAPE)(PGPKey *key))passphraseBlock;

/**
*  Removes a UserId from both public and secret keys.
*
*  @param userId should be case sensitive identical to an existing userid on the key.
*
*/
-(void)removeUserId:(NSString*)userId;


@end

NS_ASSUME_NONNULL_END
