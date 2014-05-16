//
//  NSData+Bytes.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (PGPUtils)

- (UInt16) checksum;
- (NSData*) MD5;
- (NSData*) SHA1;
- (NSData*) SHA224;
- (NSData*) SHA256;
- (NSData*) SHA384;
- (NSData*) SHA512;

@end
