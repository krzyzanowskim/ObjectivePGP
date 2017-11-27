//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPKey.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// ObjectivePGP main class.
@interface ObjectivePGP : NSObject

/// Imported keys.
@property (strong, nonatomic, readonly) NSArray<PGPKey *> *keys;

/**
 Import keys. `keys` property is updated after successfull import.

 @param keys Keys to import.
 */
- (void)importKeys:(NSArray<PGPKey *> *)keys NS_SWIFT_NAME(import(keys:));

/**
 Import key with given identifier

 @param keyIdentifier Short (8 characters) key identifier to load.
 @param path Path to the file with the keys.
 @return YES on success.
 */
- (BOOL)importKey:(NSString *)identifier fromFile:(NSString *)path NS_SWIFT_NAME(import(keyIdentifier:fromFile:));

/**
 Delete keys

 @param keys Keys to delete from the `keys` collection.
 */
- (void)deleteKeys:(NSArray<PGPKey *> *)keys NS_SWIFT_NAME(delete(keys:));

/**
 Read keys from the data. Does not import the keys.

 @param data Key or keyring data.
 @return Array of read keys.
 */
+ (NSArray<PGPKey *> *)readKeysFromData:(NSData *)data NS_SWIFT_NAME(readKeys(from:));

/**
 Read keys from the file. Does not import the keys.

 @param path Path to the keys file.
 @return Array of read keys.
 */
+ (NSArray<PGPKey *> *)readKeysFromFile:(NSString *)path NS_SWIFT_NAME(readKeys(from:));

/**
 Export, previously imported, keys of given type (public or secret) to the file at given path.

 @param type Keys type.
 @param path Full path to the destination file.
 @param error Error.
 @return YES on success.
 */
- (BOOL)exportKeysOfType:(PGPPartialKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing _Nullable *)error NS_SWIFT_NAME(export(type:to:));

/**
 Export, previously imported, single key data.

 @param key Key to export.
 @param armored Choose the format. Binary or Armored (armored is a string based format)
 @return Data, or `nil` if can't export the key.
 */
- (nullable NSData *)exportKey:(PGPKey *)key armored:(BOOL)armored NS_SWIFT_NAME(export(key:armored:));

/**
 Search imported keys for the key identifier.

 @param identifier Key identifier. Short (8 characters, e.g: "4EF122E5") or long (16 characters, e.g: "71180E514EF122E5") identifier.
 @return Key instance, or `nil` if the key is not found.
 */
- (nullable PGPKey *)findKeyWithIdentifier:(NSString *)identifier NS_SWIFT_NAME(findKey(_:));

/**
 Search imported keys for key id instance.

 @param keyID Key identifier.
 @return Key instance or `nil` if not found.
 */
- (nullable PGPKey *)findKeyWithKeyID:(PGPKeyID *)keyID NS_SWIFT_NAME(findKey(_:));

/**
 Search imported keys for given user id.

 @param userID A string based identifier (usually name with the e-mail address).
 @return Array of found keys, or empty array if not found.
 */
- (NSArray<PGPKey *> *)findKeysForUserID:(NSString *)userID NS_SWIFT_NAME(findKeys(_:));

/**
 Sign data using a key.

 @param data Data to sign.
 @param key Key to be used to sign.
 @param passphrase Optional. Passphrase for the key.
 @param detached Whether result in detachec signature only, or return input data with a signature.
 @param error Error.
 @return Signed data, or `nil` if fail.
 */
+ (nullable NSData *)sign:(NSData *)data usingKey:(PGPKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing _Nullable *)error;

/**
 Verify signed data. Validates with the imported keys.

 @param signedData Signed data.
 @param error Error
 @return YES on success.
 */
- (BOOL)verify:(NSData *)data error:(NSError * __autoreleasing _Nullable *)error;

/**
 Verify signed data, with detached signature data.

 @param signedData Signed data.
 @param signatureData Detached signature data.
 @param error Error
 @return YES on success.
 */
- (BOOL)verify:(NSData *)data withSignature:(NSData *)signature error:(NSError * __autoreleasing _Nullable *)error;

/**
 Verify signed data using given key.

 @param signedData Signed data.
 @param signatureData Detached signature data.
 @param key Key to use.
 @param error Error.
 @return YES on success.
 */
+ (BOOL)verify:(NSData *)data withSignature:(NSData *)signature usingKey:(PGPKey *)key error:(NSError * __autoreleasing _Nullable *)error;

/**
 Encrypt data using given keys. Output in binary or ASCII format.

 @param data Data to encrypt.
 @param keys Keys to use to encrypte `data`
 @param armored Whether the output data should be armored (ASCII format) or not.
 @param error Error.
 @return Encrypted data in requested format.
 */
+ (nullable NSData *)encrypt:(NSData *)data usingKeys:(NSArray<PGPKey *> *)keys armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error;


/**
 Encrypt and sign input data with given keys. Output in binary or ASCII format.

 @param data Data to encrypt and sign.
 @param keys Keys to use to encrypte `data`.
 @param signKey Key to use to sign `data`.
 @param passphrase Optional. Passphrase for signature key.
 @param armored Whether the output data should be armored (ASCII format) or not.
 @param error Error.
 @return Encrypted and signed data in requested format.
 */
+ (nullable NSData *)encrypt:(NSData *)data usingKeys:(NSArray<PGPKey *> *)keys signWithKey:(nullable PGPKey *)signKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error;


/**
 Decrypt PGP encrypted data.

 @param data data to decrypt.
 @param passphrase Optional. Passphrase for the key to decrypt.
 @param error Optional. Error.
 @return Decrypted data, or `nil` if failed.
 */
- (nullable NSData *)decrypt:(NSData *)data passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error;


/**
 Decrypt PGP encrypted data.

 @param data data to decrypt.
 @param keys private keys to use.
 @param passphrase Optional. Key passphrase.
 @param error Optional. Error.
 @return Decrypted data, or `nil` if failed.
 */
+ (nullable NSData *)decrypt:(NSData *)data usingKeys:(NSArray<PGPKey *> *)keys passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error;


/**
 Decrypt encrypted message data, and verify the signature.

 @param data Data to decrypt.
 @param passphrase Optional. Passphrase for the key to decrypt.
 @param key Key to use to decrypt message.
 @param isSigned Whether message is signed.
 @param isValid whether message is valid.
 @param isIntegrityProtected Whether message integrity is protected;
 @param error Error.
 @return Decrypted data.
 */
+ (nullable NSData *)decrypt:(NSData *)data usingKeys:(NSArray<PGPKey *> *)keys passphrase:(nullable NSString *)passphrase verifyWithKey:(nullable PGPKey *)key signed:(nullable BOOL *)isSigned valid:(nullable BOOL *)isValid integrityProtected:(nullable BOOL *)isIntegrityProtected error:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
