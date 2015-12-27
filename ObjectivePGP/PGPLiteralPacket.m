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
@end

@implementation PGPLiteralPacket

- (id)init
{
    if (self = [super init]) {
        _format = PGPLiteralPacketBinary;
    }
    return self;
}

- (instancetype) initWithData:(NSData *)rawData
{
    if (self = [self init]) {
        _literalRawData = rawData;
    }
    return self;
}

+ (PGPLiteralPacket *) literalPacket:(PGPLiteralPacketFormat)format withData:(NSData *)rawData
{
    PGPLiteralPacket *literalPacket = [[PGPLiteralPacket alloc] init];
    literalPacket.format = format;
    literalPacket.literalRawData = rawData;
    return literalPacket;
}

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
    if (filenameLength > 0) {
        self.filename = [[NSString alloc] initWithData:[packetBody subdataWithRange:(NSRange){position, filenameLength}] encoding:NSUTF8StringEncoding];
        position = position + filenameLength;
    }

    // If the special name "_CONSOLE" is used, the message is considered to be "for your eyes only".

    // data date
    UInt32 creationTimestamp = 0;
    [packetBody getBytes:&creationTimestamp range:(NSRange){position, 4}];
    creationTimestamp = CFSwapInt32BigToHost(creationTimestamp);
    self.timestamp = [NSDate dateWithTimeIntervalSince1970:creationTimestamp];
    position = position + 4;
    NSData *data = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];

    switch (self.format) {
        case PGPLiteralPacketBinary:
        case PGPLiteralPacketText:
        case PGPLiteralPacketTextUTF8:
            // don't tamper the data, otherwise signature verification fails
            self.literalRawData = data;
            break;
        default:
            break;
    }

    return position;
}

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    NSAssert(self.literalRawData, @"Missing literal data");
    if (!self.literalRawData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Missing literal data"}];
        }
        return nil;
    }

    NSMutableData *bodyData = [NSMutableData data];
    [bodyData appendBytes:&_format length:1];

    if (self.filename) {
        UInt8 filenameLength = [self.filename lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        [bodyData appendBytes:&filenameLength length:1];
        [bodyData appendBytes:[self.filename cStringUsingEncoding:NSUTF8StringEncoding] length:filenameLength];
    } else {
        UInt8 zero[] = {0x00};
        [bodyData appendBytes:&zero length:sizeof(zero)];
    }

    if (self.timestamp) {
        UInt32 timestampBytes = (UInt32)[self.timestamp timeIntervalSince1970];
        timestampBytes = CFSwapInt32HostToBig(timestampBytes);
        [bodyData appendBytes:&timestampBytes length:4];
    } else {
        UInt8 zero4[] = {0,0,0,0};
        [bodyData appendBytes:&zero4 length:4];
    }

    switch (self.format) {
        case PGPLiteralPacketText:
        case PGPLiteralPacketTextUTF8:
        case PGPLiteralPacketBinary:
            [bodyData appendData:self.literalRawData];
            break;
        default:
            break;
    }

    NSMutableData *data = [NSMutableData data];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];

    return [data copy];
}


@end
