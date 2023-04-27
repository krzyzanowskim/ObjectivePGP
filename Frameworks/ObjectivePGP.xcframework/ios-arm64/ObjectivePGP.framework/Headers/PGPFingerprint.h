//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_SWIFT_NAME(Fingerprint) @interface PGPFingerprint : NSObject

@property (nonatomic, copy) NSData *hashedData;
@property (nonatomic, copy) NSData *keyData;

- (instancetype)initWithData:(NSData *)data;
- (NSString *)description;
- (NSUInteger)hashLength;

- (NSData*)exportV4HashedData;

@end
