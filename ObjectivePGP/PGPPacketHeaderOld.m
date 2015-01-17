//
//  PGPPacketHeaderOld.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeaderOld.h"
#import "PGPPacket.h"
#import "PGPCommon.h"

@interface PGPPacketHeaderOld ()
@property (assign, readwrite) PGPPacketTag packetTag;
@property (assign, readwrite) UInt8 headerLength;
@property (assign, readwrite) UInt32 bodyLength;
@property (assign, readwrite, getter=isBodyLengthPartial) BOOL bodyLengthPartial;
@end

@implementation PGPPacketHeaderOld

- (instancetype)initWithData:(NSData *)headerData error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(headerData);
    
    if (!headerData) {
        return nil;
    }
    
    if (self = [self init]) {
        if (![self parse:headerData error:error]) {
            NSAssert(*error, @"Header parse error");
            return nil;
        }
        
    }
    return self;
}

#pragma mark - Private

- (BOOL) parse:(NSData *)headerData error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(headerData.length > 0);
    
    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte length:1];
    //  Bits 5-2 -- packet tag
    self.packetTag = ((UInt8)(headerByte << 2) >> 4);
    //  Bits 1-0 -- length-type
    UInt8 bodyLengthType = (UInt8)(headerByte << 6) >> 6;
    
    switch (bodyLengthType) {
        case 0:
        {
            NSRange range = (NSRange) {1,1};
            UInt8 oneOctet;
            [headerData getBytes:&oneOctet range:range];
            self.bodyLength = oneOctet;
            self.headerLength = 1 + range.length;
        }
            break;
        case 1:
        {
            NSRange range = (NSRange) {1,2};
            UInt16 twoOctets;
            [headerData getBytes:&twoOctets range:range];
            // value of a two-octet scalar is ((n[0] << 8) + n[1]).
            self.bodyLength = CFSwapInt16BigToHost(twoOctets);
            self.headerLength = 1 + range.length;
        }
            break;
        case 2:
        {
            NSRange range = (NSRange) {1,4};
            UInt32 fourOctets;
            [headerData getBytes:&fourOctets range:range];
            self.bodyLength = CFSwapInt32BigToHost(fourOctets);
            self.headerLength = 1 + range.length;
        }
            break;
        case 3:
        {
            #ifdef DEBUG
            NSLog(@"The packet is of indeterminate length.");
            #endif
            // The packet is of indeterminate length.  The header is 1 octet
            // long, and the implementation must determine how long the packet
            // is.
            self.bodyLength = PGPIndeterminateLength;
            self.headerLength = 1;
        }
            break;
            
        default:
            NSAssert(false, @"Invalid packet header");
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid packet header"}];
            }
            return NO;
            break;
    }

    return YES;
}


@end
