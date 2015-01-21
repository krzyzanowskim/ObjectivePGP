//
//  PGPSignatureSubpacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 20/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignatureSubpacket.h"
#import "PGPCommon.h"
#import "NSInputStream+PGP.h"
#import "PGPKeyID.h"
#import "PGPSignaturePacket.h"

@implementation PGPSignatureSubpacket

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] init];
    
    // the subpacket length (1, 2, or 5 octets)
    // Note: "The length includes the type octet but not this length"
    // Example: 02 19 01
    // length 0x02 = 2
    // type 0x19   = 25
    // body: 0x01  = 1
    // so... given body length is = 2 but body length is in fact = 1
    // this is because given body length include type octet which is from header namespace, not body really.
    // I'm drunk, or person who defined it this way was drunk.
    
    UInt8 firstOctet = [inputStream readUInt8];
    NSUInteger subpacketLength = 0;
    if (firstOctet < 192) {
        subpacketLength = firstOctet;
    } else if (firstOctet >= 192 && firstOctet < 255) {
        UInt8 secondOctet = [inputStream readUInt8];
        subpacketLength = ((firstOctet - 192) << 8) + (secondOctet) + 192;
    } else if (firstOctet == 255) {
        subpacketLength = [inputStream readUInt32];
    }

    NSUInteger subpacketLengthLeft = subpacketLength;
    // the subpacket type (1 octet),
    subpacket.type = [inputStream readUInt8];
    subpacketLengthLeft -= 1;
    
    // Bit 7 of the subpacket type is the "critical" bit.
    subpacket.critical = (subpacket.type & 0x80) == 0x80;
    if (subpacket.critical) {
        // unset critical bit
        subpacket.type = subpacket.type & ~0x80;
    }
    
    // Implementations SHOULD implement the three preferred algorithm subpackets (11, 21, and 22)
    // as well as the "Reason for Revocation" subpacket.
    switch (subpacket.type) {
        case PGPSignatureSubpacketTypeSignatureCreationTime:
        case PGPSignatureSubpacketTypeSignatureExpirationTime:
        {
            // (4 octets) The time the signature was made.
            UInt32 timestamp = [inputStream readUInt32];
            subpacket.value = [NSDate dateWithTimeIntervalSince1970:timestamp];;
            subpacketLengthLeft -= 4;
        }
            break;
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm:
        case PGPSignatureSubpacketTypePreferredHashAlgorithm:
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm:
        {
            NSMutableArray *elements = [NSMutableArray array];
            while (subpacketLengthLeft) {
                UInt8 value = [inputStream readUInt8];
                [elements addObject:@(value)];
                subpacketLengthLeft--;
            }
            subpacket.value = [elements copy];
        }
            break;
        case PGPSignatureSubpacketTypeReasonForRevocation:
            // (1 octet of revocability, 0 for not, 1 for revocable)
            subpacket.value = @([inputStream readUInt8]);
            break;
        case PGPSignatureSubpacketTypeIssuerKeyID:
        {
            UInt8 buffer[subpacketLengthLeft];
            if ([inputStream read:buffer maxLength:sizeof(buffer)] < subpacketLengthLeft) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Problem occur with signature subpacket."}];
                }
                return nil;
            }
            subpacket.value = [[PGPKeyID alloc] initWithBytes:buffer length:sizeof(buffer)];
        }
            break;
        case PGPSignatureSubpacketTypePrimaryUserID:
        {
            UInt8 buffer[subpacketLengthLeft];
            if ([inputStream read:buffer maxLength:sizeof(buffer)] < subpacketLengthLeft) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Problem occur with signature subpacket."}];
                }
                return nil;
            }
            subpacket.value = [[NSString alloc] initWithBytes:buffer length:sizeof(buffer) encoding:NSUTF8StringEncoding];
            NSAssert(subpacket.value, @"Invalid value");
        }
            break;
        case PGPSignatureSubpacketTypeKeyFlags:
            break;
        default:
            break;
    }
    return nil;
}


@end
