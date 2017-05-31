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
#import "PGPUser.h"

NS_ASSUME_NONNULL_BEGIN

@interface ObjectivePGP : NSObject

/**
 *  Array of PGPKey
 */
@property (strong, nonatomic, nonnull) NSArray<PGPKey *> *keys;

// Import keys
- (nullable NSArray<PGPKey *> *)importKeysFromFile:(NSString * )path allowDuplicates:(BOOL)duplicates;
- (nullable NSArray<PGPKey *> *)importKeysFromData:(NSData * )data allowDuplicates:(BOOL)duplicates;
- (BOOL) importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path;

// Read keys
- (nullable NSArray<PGPKey *> *)keysFromData:(NSData *)fileData;
- (nullable NSArray<PGPKey *> *)keysFromFile:(NSString *)path;

// Export keys
- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing __nullable * __nullable)error;

- (BOOL)exportKeys:(NSArray<PGPKey *> *)keys toFile:(NSString *)path error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)exportKey:(PGPKey *)key armored:(BOOL)armored;

- (nullable PGPKey *)getKeyForIdentifier:(NSString *)keyIdentifier type:(PGPKeyType)keyType;
- (nullable PGPKey *)getKeyForKeyID:(PGPKeyID *)searchKeyID type:(PGPKeyType)keyType;
- (nullable NSArray<PGPKey *> *) getKeysForUserID:(NSString *)userID;
- (NSArray<PGPKey *> *) getKeysOfType:(PGPKeyType)keyType;

- (nullable NSData *)signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(nullable NSString *)passphrase  error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(nullable NSString *)passphrase detached:(BOOL)detached  error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing __nullable * __nullable)error;

- (BOOL) verifyData:(NSData *)signedDataPackets error:(NSError * __autoreleasing __nullable * __nullable)error;
- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing __nullable * __nullable)error;
- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey error:(NSError * __autoreleasing __nullable * __nullable)error;

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingPublicKey:(PGPKey *)publicKey armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys signWithSecretKey:(nullable PGPKey *)secretKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithPublicKey:(nullable PGPKey *)publicKey signed:(nullable BOOL*)isSigned valid:(nullable BOOL*)isValid integrityProtected:(nullable BOOL*)isIntegrityProtected error:(NSError * __autoreleasing __nullable * __nullable)error;

@end

NS_ASSUME_NONNULL_END

