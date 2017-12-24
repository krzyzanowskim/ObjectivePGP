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

/// Keyring
NS_SWIFT_NAME(Keyring) @interface PGPKeyring : NSObject

/// Keys in keyring.
@property (strong, nonatomic, readonly) NSArray<PGPKey *> *keys;

/**
 Import keys. `keys` property is updated after successfull import.

 @param keys Keys to import.
 */
- (void)importKeys:(NSArray<PGPKey *> *)keys NS_SWIFT_NAME(import(keys:));

/**
 Import key with given identifier

 @param identifier Short (8 characters) key identifier to load.
 @param path Path to the file with the keys.
 @return YES on success.
 */
- (BOOL)importKey:(NSString *)identifier fromPath:(NSString *)path error:(NSError * __autoreleasing _Nullable *)error NS_SWIFT_NAME(import(keyIdentifier:fromPath:));

/**
 Delete keys

 @param keys Keys to delete from the `keys` collection.
 */
- (void)deleteKeys:(NSArray<PGPKey *> *)keys NS_SWIFT_NAME(delete(keys:));


/// Delete all keys;
- (void)deleteAll;

/**
 Export, previously imported, keys of given type (public or secret) to the file at given path.

 @param type Keys type.
 @param path Full path to the destination file.
 @param error Error.
 @return YES on success.
 */
- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing _Nullable *)error NS_SWIFT_NAME(export(type:to:));

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

@end

NS_ASSUME_NONNULL_END

