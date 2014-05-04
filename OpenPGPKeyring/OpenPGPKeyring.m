//
//  OpenPGPKeyring.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "OpenPGPKeyring.h"
#import "PGPPublicKey.h"
#import "PGPPublicSubKey.h"

@implementation OpenPGPKeyring

- (BOOL) open:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath]) {
        return NO;
    }

    NSData *ringData = [NSData dataWithContentsOfFile:fullPath];
    if (!ringData) {
        return NO;
    }

    [self parseKeyring:ringData];
    return YES;
}

#pragma mark - Parse keyring

- (BOOL) parseKeyring:(NSData *)keyringData
{
    BOOL ret = NO;

    NSUInteger offset = 0;

    //TODO: add loop here to read all packets from file
    //      whole keyring is parsed at once, for big files it may be a problem
    NSUInteger bodyLength = 0;
    PGPPacketTag packetTag = 0;
    NSData *packetHeaderData = [keyringData subdataWithRange:(NSRange) {offset + 0,MIN(6,keyringData.length)}]; // up to 6 octets for complete header
    NSUInteger headerLength = [self parsePacketHeader:packetHeaderData bodyLength:&bodyLength packetTag:&packetTag];

    NSData *packetBodyData = [keyringData subdataWithRange:(NSRange) {offset + headerLength,bodyLength}];
    [self parsePacketTag:packetTag packetBody:packetBodyData];
    return ret;
}

#pragma mark - Packet header

// 4.2.  Packet Headers
/**
 *  Parse header
 *
 *  @param headerData header data
 *  @param length     return packet body length
 *  @param tag        return packet tag
 *
 *  @return Header length
 */
- (NSUInteger) parsePacketHeader:(NSData *)headerData bodyLength:(NSUInteger *)length packetTag:(PGPPacketTag *)tag
{
    UInt8 *headerBytes = (UInt8 *)[headerData subdataWithRange:NSMakeRange(0, 1)].bytes;
    UInt8 headerByte = headerBytes[0];

    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    BOOL isNewFormat = !!(headerByte & PGPHeaderPacketTagNewFormat);

    *length = 0;

    if (!isPGPHeader) {
        return 0;
    }

    NSUInteger headerLength = 0;
    if (isNewFormat) {
        headerLength = [self parseNewFormatHeaderPacket:headerData bodyLength:length packetTag:tag];
    } else {
        headerLength = [self parseOldFormatHeaderPacket:headerData bodyLength:length packetTag:tag];
    }

    return headerLength;
}

/**
 *  4.2.  Packet Headers
 *
 *  @param packetData Packet header
 *
 *  @return Header length
 */
- (NSUInteger) parseNewFormatHeaderPacket:(NSData *)headerData bodyLength:(NSUInteger *)length packetTag:(PGPPacketTag *)tag
{
    UInt8 *headerBytes = (UInt8 *)[headerData subdataWithRange:NSMakeRange(0, 1)].bytes;
    // Bits 5-0 -- packet tag
    UInt8 packetTag = (headerBytes[0] << 2);
    packetTag = (packetTag >> 2);
    *tag = packetTag;

    // body length
    BOOL isPartialBodyLength = NO;
    UInt32 bodyLength        = 0;
    NSInteger headerLength   = 2;

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(1, 5)].bytes;

    UInt8 firstOctet  = lengthOctets[0];
    UInt8 secondOctet = lengthOctets[1];
    UInt8 thirdOctet  = lengthOctets[2];
    UInt8 fourthOctet = lengthOctets[3];
    UInt8 fifthOctet  = lengthOctets[4];

    if (firstOctet < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        bodyLength        = firstOctet;
        headerLength = 1 + 1;
    } else if (firstOctet >= 192 && firstOctet <= 223) {
        // 4.2.2.2.  Two-Octet Lengths
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        bodyLength        = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        headerLength = 1 + 2;
    } else if (firstOctet >= 223 && firstOctet < 255) {
        // 4.2.2.4.  Partial Body Length
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        UInt32 partianBodyLength = CFSwapInt32BigToHost(firstOctet << (firstOctet & 0x1F));
        bodyLength               = partianBodyLength;
        headerLength        = 1 + 1;
        isPartialBodyLength      = YES;
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        bodyLength        = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet;
        headerLength = 1 + 5;
    }
    *length = bodyLength;
    return headerLength;
}

// 4.2.  Packet Headers
- (NSUInteger) parseOldFormatHeaderPacket:(NSData *)packetData bodyLength:(NSUInteger *)length packetTag:(PGPPacketTag *)tag
{
    //TODO: read old format
    @throw [NSException exceptionWithName:@"PGPUnknownFormat" reason:@"Old format is not supported" userInfo:nil];
    return 0;
}

#pragma mark - Packet body

/**
 *  Determine packet type
 *
 *  @param packetTag  Packet tag
 *  @param packetBody Packet Body
 */
- (void) parsePacketTag:(PGPPacketTag)packetTag packetBody:(NSData *)packetBody
{
    NSLog(@"Reading packet tag %#x", packetTag);
    
    switch (packetTag) {
        case PGPPublicKeyPacketTag:
        {
            PGPPublicKey *publicKey = [[PGPPublicKey alloc] init];
            [publicKey parsePacketBody:packetBody];
        }
            break;
        case PGPPublicSubkeyPacketTag:
        {
            PGPPublicSubKey *publicSubKey = [[PGPPublicSubKey alloc] init];
            [publicSubKey parsePacketBody:packetBody];
        }
            break;

        default:
            break;
    }
}

@end
