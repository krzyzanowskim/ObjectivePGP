//
//  PGPKeyID.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPFingerprint.h"

@interface PGPKeyID : NSObject

@property (readonly, nonatomic) NSData *longKey;
@property (readonly, nonatomic) NSString *longKeyString;
@property (readonly, nonatomic) NSData *shortKey;
@property (readonly, nonatomic) NSString *shortKeyString;

- (instancetype) initWithFingerprint:(PGPFingerprint *)fingerprint;
- (instancetype) initWithLongKey:(NSData *)longKeyData;

- (BOOL) isEqualToKeyID:(PGPKeyID *)keyID;

- (NSData *)exportKeyData;

@end
