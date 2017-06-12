//
//  ObjectivePGP.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPFoundation.h"
#import "PGPCompoundKey.h"

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// ObjectivePGP main class.
@interface ObjectivePGP : NSObject

/// Imported keys.
@property (strong, nonatomic, readonly) NSSet<PGPCompoundKey *> *keys;

/**
 Import keys from the file. `keys` property is updated after successfull import.

 @param path Path to the file with the keys.
 @return Array of loaded keys.
 */
- (NSArray<PGPCompoundKey *> *)importKeysFromFile:(NSString *)path;

/**
 Import keys from the data. `keys` property is updated after successfull import.

 @param data Keys data.
 @return Array of loaded keys.
 */
- (NSArray<PGPCompoundKey *> *)importKeysFromData:(NSData *)data;

/**
 Import key with given identifier

 @param shortKeyStringIdentifier Short (8 characters) key identifier to load.
 @param path Path to the file with the keys.
 @return YES on success.
 */
- (BOOL)importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path;

/**
 Read keys from the data. Does not import the keys.

 @param fileData Keys data.
 @return Array of parsed keys.
 */
- (NSArray<PGPCompoundKey *> *)keysFromData:(NSData *)fileData;

/**
 Read keys from the file. Does not import the keys.

 @param path Path to the keys file.
 @return Array of parsed keys.
 */
- (NSArray<PGPCompoundKey *> *)keysFromFile:(NSString *)path;

/**
 Save keys of given type (public or private) to the file.

 @param type Keys type.
 @param path Full path to the destination file.
 @param error Error.
 @return YES on success.
 */
- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing _Nullable *)error;

/**
 Export key data.

 @param key Key to export.
 @param armored Choose the format. Binary or Armored (armored is a string based format)
 @return Data or `nil` if can't export key.
 */
- (nullable NSData *)exportKey:(PGPCompoundKey *)key armored:(BOOL)armored;

/**
 Search for string based key identifier.

 @param keyIdentifier Key identifier. Short (8 characters, e.g: 4EF122E5) or long (16 characters, e.g: 71180E514EF122E5) identifier.
 @return Key instance, or `nil` if not found.
 */
- (nullable PGPCompoundKey *)findKeyForIdentifier:(NSString *)keyIdentifier;

/**
 Search for key id.

 @param keyID Key identifier.
 @return Key instance or `nil` if not found.
 */
- (nullable PGPCompoundKey *)findKeyForKeyID:(PGPKeyID *)keyID;

/**
 Search for keys for given user id.

 @param userID A string based identifier (usually name with the e-mail address).
 @return Array of found keys, or empty array if not found.
 */
- (NSArray<PGPCompoundKey *> *)findKeysForUserID:(NSString *)userID;

/**
 Sign data using a key.

 @param dataToSign Data to sign.
 @param key Key to be used to sign.
 @param passphrase Optional. Passphrase for the key.
 @param detached whether output detached signature.
 @param error Error.
 @return Signed data, or `nil` if fail.
 */
- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPCompoundKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing _Nullable *)error;

/**
 Verify signed data. Validates with the imported keys.

 @param signedData Signed data.
 @param error Error
 @return YES on success.
 */
- (BOOL)verifyData:(NSData *)signedData error:(NSError * __autoreleasing _Nullable *)error;

/**
 Verify signed data, with detached signature data.

 @param signedData Signed data.
 @param signatureData Detached signature data.
 @param error Error
 @return YES on success.
 */
- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing _Nullable *)error;
/**
 Verify signed data using given key.

 @param signedData Signed data.
 @param signatureData Detached signature data.
 @param key Key to use.
 @param error Error.
 @return YES on success.
 */
- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPCompoundKey *)key error:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPCompoundKey *> *)keys armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPCompoundKey *> *)keys signWithKey:(nullable PGPCompoundKey *)signKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithKey:(nullable PGPCompoundKey *)key signed:(nullable BOOL *)isSigned valid:(nullable BOOL *)isValid integrityProtected:(nullable BOOL *)isIntegrityProtected error:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END

