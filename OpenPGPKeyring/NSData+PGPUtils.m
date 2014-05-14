//
//  NSData+PGPUtils.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "NSData+PGPUtils.h"
#import <CommonCrypto/CommonDigest.h>

@implementation NSData (PGPUtils)



/**
 *  Calculates a 16bit sum of a string by adding each character * codes modulus 65535
 *
 *  @return checksum
 */
- (UInt16) checksum
{
    UInt16 s = 0;
    UInt8 *bytes = (UInt8 *)self.bytes;
    for (NSUInteger i = 0; i < self.length; i++) {
        s = (s + (UInt8)bytes[i]);
    }
    s = s % 65536;
    return s;
}

//- (NSData*) MD5
//{
//	unsigned int outputLength = CC_MD5_DIGEST_LENGTH;
//	unsigned char output[outputLength];
//
//	CC_MD5(self.bytes, (unsigned int) self.length, output);
//	return [NSMutableData dataWithBytes:output length:outputLength];
//}

- (NSData *) SHA1
{
    if (!self)
        return self;
    
    CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA1_Init(ctx);
    CC_SHA1_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_SHA1_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    CC_SHA1_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA1_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

//- (NSData*) SHA256
//{
//	unsigned int outputLength = CC_SHA256_DIGEST_LENGTH;
//	unsigned char output[outputLength];
//
//	CC_SHA256(self.bytes, (unsigned int) self.length, output);
//	return [NSMutableData dataWithBytes:output length:outputLength];
//}


//- (NSNumber *) numberWithBytes:(NSRange)range
//{
//    for (t = 0, n = 0; n < len; ++n) {
//		t = (t << 8) + c[n];
//	}
//}

@end
