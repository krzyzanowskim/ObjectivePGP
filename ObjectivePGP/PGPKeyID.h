//
//  PGPKeyID.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPFingerprint.h"
#import "PGPFoundation.h"

@interface PGPKeyID : NSObject

@property (readonly, copy, nonatomic) NSData *longKey;
@property (readonly, nonatomic) NSString *longKeyString;
@property (readonly, nonatomic) NSData *shortKey;
@property (readonly, nonatomic) NSString *shortKeyString;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithLongKey:(NSData *)longKeyData NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithFingerprint:(PGPFingerprint *)fingerprint;

- (BOOL)isEqualToKeyID:(PGPKeyID *)keyID;

- (NSData *)exportKeyData;

@end
