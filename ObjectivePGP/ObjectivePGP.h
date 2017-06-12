//
//  ObjectivePGP.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPKey.h"
#import "PGPCompoundKey.h"
#import "PGPUser.h"

NS_ASSUME_NONNULL_BEGIN

@interface ObjectivePGP : NSObject

// Keys. Updated on import.
@property (strong, nonatomic, readonly) NSMutableSet<PGPCompoundKey *> *keys;

// Import keys
- (NSArray<PGPCompoundKey *> *)importKeysFromFile:(NSString *)path;
- (NSArray<PGPCompoundKey *> *)importKeysFromData:(NSData *)data;
- (BOOL) importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path;

// Read keys
- (NSArray<PGPCompoundKey *> *)keysFromData:(NSData *)fileData;
- (NSArray<PGPCompoundKey *> *)keysFromFile:(NSString *)path;

// Export keys
- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing __nullable * __nullable)error;

- (nullable NSData *)exportKey:(PGPCompoundKey *)key armored:(BOOL)armored;

/// 16 or 8 characters long identifier.
- (nullable PGPCompoundKey *)getKeyForIdentifier:(NSString *)keyIdentifier;
- (nullable PGPCompoundKey *)getKeyForKeyID:(PGPKeyID *)searchKeyID;
/// Returns keys for the full user identifier.
- (NSArray<PGPCompoundKey *> *)getKeysForUserID:(NSString *)userID;

- (nullable NSData *)signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(nullable NSString *)passphrase  error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_MSG_ATTRIBUTE("Use PGPCompoundKey version. ");
- (nullable NSData *)signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(nullable NSString *)passphrase detached:(BOOL)detached  error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_MSG_ATTRIBUTE("Use PGPCompoundKey version.");

- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPCompoundKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing *)error;

- (nullable NSData *)signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing __nullable * __nullable)error;

- (BOOL)verifyData:(NSData *)signedDataPackets error:(NSError * __autoreleasing __nullable * __nullable)error;
- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_ATTRIBUTE;
- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_ATTRIBUTE;

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKey:(PGPCompoundKey *)key armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_ATTRIBUTE;
- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys signWithSecretKey:(nullable PGPKey *)secretKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_ATTRIBUTE;
- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_ATTRIBUTE;
- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithPublicKey:(nullable PGPKey *)publicKey signed:(nullable BOOL*)isSigned valid:(nullable BOOL*)isValid integrityProtected:(nullable BOOL*)isIntegrityProtected error:(NSError * __autoreleasing __nullable * __nullable)error DEPRECATED_ATTRIBUTE;

@end

NS_ASSUME_NONNULL_END

