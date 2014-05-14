//
//  PGPFingerprint.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 14/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPFingerprint : NSObject
@property (copy) NSData *data;

- (instancetype) initWithData:(NSData *)data;
- (NSString *) description;
- (NSUInteger) length;

@end
