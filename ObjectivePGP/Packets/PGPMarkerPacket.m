//
//
//  ObjectivePGP
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPMarkerPacket.h"

@interface PGPMarkerPacket ()

@property (nonatomic, copy, readwrite) NSData *data;

@end

@implementation PGPMarkerPacket

- (PGPPacketTag)tag {
    return PGPMarkerPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    self.data = packetBody;

    // The body of this packet consists of:
    // - The three octets 0x50, 0x47, 0x50 (which spell "PGP" in UTF-8).
    BOOL isValid = packetBody.length != 3 || [packetBody isEqual:[@"PGP" dataUsingEncoding:NSASCIIStringEncoding]];
    if (!isValid) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"The packet is invalid" }];
        }
        return position;
    }

    return position;
}

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    return [PGPPacket buildPacketOfType:PGPUserAttributePacketTag withBody:^NSData * {
        return self.data;
    }];
}

@end
