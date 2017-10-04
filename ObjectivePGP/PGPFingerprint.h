//
//  PGPFingerprint.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 14/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_SWIFT_NAME(Fingerprint) @interface PGPFingerprint : NSObject

@property (nonatomic, copy) NSData *hashedData;
@property (nonatomic, copy) NSData *keyData;

- (instancetype)initWithData:(NSData *)data;
- (NSString *)description;
- (NSUInteger)hashLength;

@end
