//
//  PGPFingerprint.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 14/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPFingerprint : NSObject
@property (copy) NSData *hashedData;
@property (copy) NSData *keyData;

- (instancetype) initWithData:(NSData *)data;
- (NSString *) description;
- (NSUInteger) hashLength;

- (BOOL) isEqualToFingerprint:(PGPFingerprint *)fingerprint;

@end
