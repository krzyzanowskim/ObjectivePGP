//
//  PGPUserIDPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserIDPacket.h"
#import "NSInputStream+PGP.h"
#import "NSOutputStream+PGP.h"
#import "PGPCommon.h"

@implementation PGPUserIDPacket

+ (instancetype) readFromStream:(NSInputStream *)inputStream maxLength:(NSUInteger)length error:(NSError * __autoreleasing *)error
{
    PGPUserIDPacket *packet = [[PGPUserIDPacket alloc] init];
    
    UInt8 buffer[length];
    NSInteger result = [inputStream read:buffer maxLength:length];
    if (result < 0 || result < length) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Can't read User ID packet."}];
        }
        return nil;
    }
    
    packet.userID = [[NSString alloc] initWithBytes:buffer length:length encoding:NSUTF8StringEncoding];

    // forget buffer
    memset(buffer, arc4random(), length);

    return packet;
}

- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(outputStream);
    
    NSUInteger maxLength = [self.userID lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    void *buffer = calloc(1, maxLength);
    [self.userID getBytes:buffer
                maxLength:maxLength
               usedLength:nil
                 encoding:NSUTF8StringEncoding
                  options:NSStringEncodingConversionAllowLossy
                    range:NSMakeRange(0, self.userID.length)
           remainingRange:nil];
    
    [outputStream write:buffer maxLength:[self.userID lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];

    memset(buffer, arc4random(), maxLength);
    free(buffer);
    
    return YES;
}

@end
