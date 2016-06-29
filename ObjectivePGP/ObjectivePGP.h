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

@interface ObjectivePGP : NSObject

/**
 *  Array of PGPKey
 */
@property (strong, nonatomic, nonnull) NSArray<PGPKey *> *keys;

// Import keys
- (NSArray * __nullable) importKeysFromFile:(NSString * __nonnull)path allowDuplicates:(BOOL)duplicates;
- (NSArray * __nullable) importKeysFromData:(NSData * __nonnull)data allowDuplicates:(BOOL)duplicates;
- (BOOL) importKey:(nonnull NSString *)shortKeyStringIdentifier fromFile:(nonnull NSString *)path;

// Read keys
- (nullable NSArray<PGPKey *> *) keysFromData:(nonnull NSData *)fileData;
- (nullable NSArray<PGPKey *> *) keysFromFile:(nonnull NSString *)path;

// Export keys
- (BOOL) exportKeysOfType:(PGPKeyType)type toFile:(nonnull NSString *)path error:(NSError * __autoreleasing __nullable * __nullable)error;

- (BOOL) exportKeys:(nonnull NSArray<PGPKey *> *)keys toFile:(nonnull NSString *)path error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) exportKey:(nonnull PGPKey *)key armored:(BOOL)armored;

- (nullable PGPKey *) getKeyForIdentifier:(nonnull NSString *)keyIdentifier type:(PGPKeyType)keyType;
- (nullable PGPKey *) getKeyForKeyID:(nonnull PGPKeyID *)searchKeyID type:(PGPKeyType)keyType;
- (nullable NSArray<PGPKey *> *) getKeysForUserID:(nonnull NSString *)userID;
- (nonnull NSArray<PGPKey *> *) getKeysOfType:(PGPKeyType)keyType;

- (nullable NSData *) signData:(nonnull NSData *)dataToSign usingSecretKey:(nonnull PGPKey *)secretKey passphrase:(nullable NSString *)passphrase  error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) signData:(nonnull NSData *)dataToSign usingSecretKey:(nonnull PGPKey *)secretKey passphrase:(nullable NSString *)passphrase detached:(BOOL)detached  error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) signData:(nonnull NSData *)dataToSign withKeyForUserID:(nonnull NSString *)userID passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) signData:(nonnull NSData *)dataToSign withKeyForUserID:(nonnull NSString *)userID passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing __nullable * __nullable)error;

- (BOOL) verifyData:(nonnull NSData *)signedDataPackets error:(NSError * __autoreleasing __nullable * __nullable)error;
- (BOOL) verifyData:(nonnull NSData *)signedData withSignature:(nonnull NSData *)signatureData error:(NSError * __autoreleasing __nullable * __nullable)error;
- (BOOL) verifyData:(nonnull NSData *)signedData withSignature:(nonnull NSData *)signatureData usingKey:(nonnull PGPKey *)publicKey error:(NSError * __autoreleasing __nullable * __nullable)error;

- (nullable NSData *) encryptData:(nonnull NSData *)dataToEncrypt usingPublicKey:(nonnull PGPKey *)publicKey armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) encryptData:(nonnull NSData *)dataToEncrypt usingPublicKeys:(nonnull NSArray *)publicKeys armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) encryptData:(nonnull NSData *)dataToEncrypt usingPublicKeys:(nonnull NSArray *)publicKeys signWithSecretKey:(nullable PGPKey *)secretKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) decryptData:(nonnull NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing __nullable * __nullable)error;
- (nullable NSData *) decryptData:(nonnull NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithPublicKey:(nullable PGPKey *)publicKey signed:(nullable BOOL*)isSigned valid:(nullable BOOL*)isValid integrityProtected:(nullable BOOL*)isIntegrityProtected error:(NSError * __autoreleasing __nullable * __nullable)error;

@end
