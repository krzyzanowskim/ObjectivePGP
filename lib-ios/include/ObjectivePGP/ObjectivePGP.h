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
@property (strong, nonatomic) NSArray *keys;

// Import keys
- (NSArray *) importKeysFromFile:(NSString *)path allowDuplicates:(BOOL)duplicates;
- (NSArray *) importKeysFromData:(NSData *)data allowDuplicates:(BOOL)duplicates;
- (BOOL) importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path;

// Read keys
- (NSArray *) keysFromData:(NSData *)fileData;
- (NSArray *) keysFromFile:(NSString *)path;

// Export keys
- (BOOL) exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing *)error;
- (BOOL) exportKeys:(NSArray *)keys toFile:(NSString *)path error:(NSError * __autoreleasing *)error;
- (NSData *) exportKey:(PGPKey *)key armored:(BOOL)armored;

- (PGPKey *) getKeyForIdentifier:(NSString *)keyIdentifier type:(PGPKeyType)keyType;
- (PGPKey *) getKeyForKeyID:(PGPKeyID *)searchKeyID type:(PGPKeyType)keyType;
- (NSArray *) getKeysForUserID:(NSString *)userID;
- (NSArray *) getKeysOfType:(PGPKeyType)keyType;

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase  error:(NSError * __autoreleasing *)error;
- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase detached:(BOOL)detached  error:(NSError * __autoreleasing *)error;
- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase error:(NSError * __autoreleasing *)error;
- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing *)error;

- (BOOL) verifyData:(NSData *)signedDataPackets error:(NSError * __autoreleasing *)error;
- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing *)error;
- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey error:(NSError * __autoreleasing *)error;

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKey:(PGPKey *)publicKey armored:(BOOL)armored error:(NSError * __autoreleasing *)error;
- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys armored:(BOOL)armored error:(NSError * __autoreleasing *)error;
- (NSData *) decryptData:(NSData *)messageDataToDecrypt passphrase:(NSString *)passphrase error:(NSError * __autoreleasing *)error;

@end
