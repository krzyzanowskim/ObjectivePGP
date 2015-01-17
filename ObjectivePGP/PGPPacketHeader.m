//
//  PGPPacketHeader.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeader.h"
#import "PGPPacketHeaderNew.h"
#import "PGPPacketHeaderOld.h"
#import "PGPCommon.h"

@interface PGPPacketHeader ()
@end

@implementation PGPPacketHeader

+ (id <PGPPacketHeader> )packetHeaderWithData:(NSData *)headerData error:(NSError * __autoreleasing *)error;
{
    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte range:(NSRange){0,1}];
    
    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    if (!isPGPHeader) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid sequence of packet header bytes"}];
        }
        return nil;
    }
    
    BOOL isNewFormat = !!(headerByte & PGPHeaderPacketTagNewFormat);
    if (isNewFormat) {
        return [[PGPPacketHeaderNew alloc] initWithData:headerData];
    }

    return nil;
}

@end
