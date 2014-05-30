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

@interface ObjectivePGP : NSObject

/**
 *  Array of PGPKey
 */
@property (strong, nonatomic) NSArray *keys;

- (BOOL) loadKeysFromKeyring:(NSString *)path;
- (BOOL) loadKey:(NSString *)shortKeyStringIdentifier fromKeyring:(NSString *)path;

- (BOOL) saveKeysOfType:(PGPKeyType)type toKeyring:(NSString *)path error:(NSError **)error;
- (BOOL) saveKeys:(NSArray *)keys toKeyring:(NSString *)path error:(NSError **)error;

- (NSArray *) getKeysForUserID:(NSString *)userID;
- (PGPKey *)  getKeyForIdentifier:(NSString *)keyIdentifier;
- (NSArray *) getKeysOfType:(PGPKeyType)keyType;

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase;
- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase detached:(BOOL)detached;
- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase;
- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase detached:(BOOL)detached;

- (BOOL) verifyData:(NSData *)signedData;
- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData;
- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey;

@end
