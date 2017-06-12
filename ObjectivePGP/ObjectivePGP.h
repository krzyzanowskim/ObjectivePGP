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

@interface ObjectivePGP : NSObject

// Keys. Updated on import.
@property (strong, nonatomic, readonly) NSSet<PGPCompoundKey *> *keys;

// Import keys
- (NSArray<PGPCompoundKey *> *)importKeysFromFile:(NSString *)path;
- (NSArray<PGPCompoundKey *> *)importKeysFromData:(NSData *)data;
- (BOOL)importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path;

// Read keys
- (NSArray<PGPCompoundKey *> *)keysFromData:(NSData *)fileData;
- (NSArray<PGPCompoundKey *> *)keysFromFile:(NSString *)path;

// Export keys
- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)exportKey:(PGPCompoundKey *)key armored:(BOOL)armored;

/// 16 or 8 characters long identifier.
- (nullable PGPCompoundKey *)findKeyForIdentifier:(NSString *)keyIdentifier;
- (nullable PGPCompoundKey *)findKeyForKeyID:(PGPKeyID *)searchKeyID;
/// Returns keys for the full user identifier.
- (NSArray<PGPCompoundKey *> *)findKeysForUserID:(NSString *)userID;

- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPCompoundKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing _Nullable *)error;

- (BOOL)verifyData:(NSData *)signedData error:(NSError * __autoreleasing _Nullable *)error;
- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing _Nullable *)error;
- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPCompoundKey *)key error:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPCompoundKey *> *)keys armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPCompoundKey *> *)keys signWithKey:(nullable PGPCompoundKey *)signKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithKey:(nullable PGPCompoundKey *)key signed:(nullable BOOL *)isSigned valid:(nullable BOOL *)isValid integrityProtected:(nullable BOOL *)isIntegrityProtected error:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END

