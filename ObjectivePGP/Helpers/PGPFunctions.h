//
//  PGPFunctions.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 21/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

#pragma once

UInt8 *pgpCalculateSHA512(const void *bytes, unsigned int length);
UInt8 *pgpCalculateSHA384(const void *bytes, unsigned int length);
UInt8 *pgpCalculateSHA256(const void *bytes, unsigned int length);
UInt8 *pgpCalculateSHA224(const void *bytes, unsigned int length);
UInt8 *pgpCalculateSHA1(const void *bytes, unsigned int length);
UInt8 *pgpCalculateMD5(const void *bytes, unsigned int length);
NSUInteger pgpNumBits(Byte *bytes, NSUInteger maxLength);
NSInteger isPowerOfTwo (NSUInteger x);
NSData *buildNewFormatLengthBytesForData(NSData *bodyData);


