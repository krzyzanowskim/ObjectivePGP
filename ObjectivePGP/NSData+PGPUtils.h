//
//  NSData+Bytes.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (PGPUtils)

- (UInt16) pgpChecksum;
- (UInt32) pgpCRC24;
- (NSData*) pgpMD5;
- (NSData*) pgpSHA1;
- (NSData*) pgpSHA224;
- (NSData*) pgpSHA256;
- (NSData*) pgpSHA384;
- (NSData*) pgpSHA512;
- (NSData*) pgpRIPEMD160;

@end
