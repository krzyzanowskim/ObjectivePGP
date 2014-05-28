//
//  PGPLiteralPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPLiteralPacket.h"
#import "PGPTypes.h"

@interface PGPLiteralPacket ()
@property (strong) NSData *literalRawData;
@end

@implementation PGPLiteralPacket

- (PGPPacketTag)tag
{
    return PGPLiteralDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // A one-octet field that describes how the data is formatted.
    [packetBody getBytes:&_format range:(NSRange){position, 1}];
    position = position + 1;

    NSAssert(self.format == PGPLiteralPacketBinary || self.format == PGPLiteralPacketText || self.format == PGPLiteralPacketTextUTF8, @"Unkown data format");
    if (self.format != PGPLiteralPacketBinary && self.format != PGPLiteralPacketText && self.format != PGPLiteralPacketTextUTF8)
    {
        // skip
        return 1 + packetBody.length;
    }

    UInt8 filenameLength = 0;
    [packetBody getBytes:&filenameLength range:(NSRange){position, 1}];
    position = position + 1;

    // filename
    self.filename = [[NSString alloc] initWithData:[packetBody subdataWithRange:(NSRange){position, filenameLength}] encoding:NSUTF8StringEncoding];
    position = position + filenameLength;

    // If the special name "_CONSOLE" is used, the message is considered to be "for your eyes only".

    // data date
    UInt32 creationTimestamp = 0;
    [packetBody getBytes:&creationTimestamp length:4];
    creationTimestamp = CFSwapInt32BigToHost(creationTimestamp);
    self.timestamp = [NSDate dateWithTimeIntervalSince1970:creationTimestamp];
    position = position + 4;

    switch (self.format) {
        case PGPLiteralPacketBinary:
        {
            self.literalRawData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
        }
            break;
        case PGPLiteralPacketText:
        case PGPLiteralPacketTextUTF8:
        {
            NSString *literalString = [[NSString alloc] initWithData:self.literalRawData encoding:NSUTF8StringEncoding];
            // Text data is stored with <CR><LF>
            // These should be converted to native line endings by the receiving software.
            NSString *literalStringWithHostNewLine = [[literalString componentsSeparatedByString:@"\r\n"] componentsJoinedByString:@"\n"];
            self.literalRawData = [literalStringWithHostNewLine dataUsingEncoding:NSUTF8StringEncoding];
        }
            break;
        default:
            break;
    }

    return position;
}

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    NSAssert(self.literalRawData, @"Missing literal data");

    NSMutableData *data = [NSMutableData data];
    [data appendBytes:&_format length:1];

    UInt8 filenameLength = [self.filename lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    [data appendBytes:&filenameLength length:1];
    [data appendBytes:[self.filename cStringUsingEncoding:NSUTF8StringEncoding] length:filenameLength];

    UInt32 timestampBytes = [self.timestamp timeIntervalSince1970];
    timestampBytes = CFSwapInt32HostToBig(timestampBytes);
    [data appendBytes:&timestampBytes length:4];

    switch (self.format) {
        case PGPLiteralPacketBinary:
            [data appendData:self.literalRawData];
            break;
        case PGPLiteralPacketText:
        case PGPLiteralPacketTextUTF8:
        {
            // Convert to <CR><LF>
            NSString *literalStringWithHostNewLine = [[NSString alloc] initWithData:self.literalRawData encoding:NSUTF8StringEncoding];
            NSString *literalStringWithCRLF = [[literalStringWithHostNewLine componentsSeparatedByString:@"\n"] componentsJoinedByString:@"\r\n"];
            [data appendData:[literalStringWithCRLF dataUsingEncoding:NSUTF8StringEncoding]];
        }
            break;
        default:
            break;
    }

    return [data copy];
}


@end
