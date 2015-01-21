//
//  PGPKeyID.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 20/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//  3.3.  Key IDs
//
//  A Key ID is an eight-octet scalar that identifies a key.
//  Implementations SHOULD NOT assume that Key IDs are unique.  The
//  section "Enhanced Key Formats" below describes how Key IDs are
//  formed.

#import <Foundation/Foundation.h>

@interface PGPKeyID : NSObject
@property (copy, readonly) NSData *octetsData;

- (instancetype) initWithBytes:(const void *)bytes length:(NSUInteger)length;
- (BOOL) isEqualToKeyID:(PGPKeyID *)keyID;

@end
