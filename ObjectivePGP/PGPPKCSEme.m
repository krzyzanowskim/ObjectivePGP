//
//  PGPPKCSEme.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPKCSEme.h"
#import "PGPTypes.h"
#import "NSData+PGPUtils.h"
#import "PGPCryptoUtils.h"

@implementation PGPPKCSEme

+ (NSData *) encodeMessage:(NSData *)m keyModulusLength:(NSUInteger)k error:(NSError * __autoreleasing *)error
{
    if (m.length > k - 11) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Message to long"}];
        }
        return nil;
    }
    
    // Generate an octet string PS of length k - mLen - 3 consisting of
    // pseudo-randomly generated nonzero octets.  The length of PS will
    // be at least eight octets.
    NSMutableData *psData = [NSMutableData data];
    for (NSUInteger i = 0; i < (k - m.length) - 3; i++) {
        UInt8 b = arc4random_uniform(254) + 1;
        [psData appendBytes:&b length:1];
    }
    
    NSMutableData *emData = [NSMutableData data];
    UInt8 emPrefix[] = {0x00, 0x02};
    UInt8 emSuffix[] = {0x00};
    [emData appendBytes:emPrefix length:sizeof(emPrefix)];
    [emData appendData:psData];
    [emData appendBytes:emSuffix length:sizeof(emSuffix)];
    [emData appendData:m];
    return [emData copy];
}

+ (NSData *)decodeMessage:(NSData *)m error:(NSError * __autoreleasing *)error
{
    NSUInteger position = 0;
    UInt8 emPrefix[2];
    [m getBytes:&emPrefix range:(NSRange){position, sizeof(emPrefix)}];
    position = position + sizeof(emPrefix);
    
    // read until 0x00
    NSUInteger *psLength = 0;
    Byte b = 0;
    do {
        [m getBytes:&b range:(NSRange){position, 1}];
        position = position + 1;
        psLength = psLength + 1;
    } while (b != 0x00 && position < (m.length - 1));

    // last read is separator 0x00, so current position at start of M
    NSData *emData = [m subdataWithRange:(NSRange){position, m.length - position}];
    return emData;
}

@end
