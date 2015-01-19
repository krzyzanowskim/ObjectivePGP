//
//  PGPUserIDPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserIDPacket.h"
#import "PGPCommon.h"

@implementation PGPUserIDPacket

+ (instancetype) readFromStream:(NSInputStream *)inputStream length:(NSUInteger)length error:(NSError * __autoreleasing *)error
{
    PGPUserIDPacket *packet = [[PGPUserIDPacket alloc] init];
    
    UInt8 *buffer = calloc(1, length);
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
    free(buffer);

    return packet;
}
@end
