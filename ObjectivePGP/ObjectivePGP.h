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

/**
 *  Load keyring file (pubring or secring. Keys are appended to *keys*.
 *
 *  @param path Path to keyring file
 *
 *  @return YES on success;
 */
- (BOOL) loadKeyring:(NSString *)path;

/**
 *  Save keys to file. If file exsits, append data.
 *
 *  @param type Secret or public
 *  @param path File path
 *
 *  @return YES on success
 */
- (BOOL) saveKeys:(PGPKeyType)type toFile:(NSString *)path;

/**
 *  Sign data with default hash algorithm
 *
 *  @param dataToSign Data to sign
 *  @param secretKey  secret key to use
 *
 *  @return Signature
 */
- (NSData *) signData:(NSData *)dataToSign withSecretKey:(PGPKey *)secretKey;


@end
