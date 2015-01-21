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
    NSUInteger length = 0;
    NSUInteger lengthOfLength = 0;
    if (firstOctet < 192) {
        length  = firstOctet;
        lengthOfLength = 1;
    } else if (firstOctet >= 192 && firstOctet < 255) {
        UInt8 secondOctet = [inputStream readUInt8];
        length   = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        lengthOfLength = 2;
    } else if (firstOctet == 255) {
        length  = [inputStream readUInt32];
        lengthOfLength = 5;
    }
    subpacket.totalLength = length + lengthOfLength;
    NSUInteger lengthLeft = length;

    // the subpacket type (1 octet),
    subpacket.type = [inputStream readUInt8];
    lengthLeft -= 1;
    
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
            lengthLeft -= 4;
        }
            break;
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm:
        case PGPSignatureSubpacketTypePreferredHashAlgorithm:
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm:
        {
            NSMutableArray *elements = [NSMutableArray array];
            while (lengthLeft) {
                UInt8 value = [inputStream readUInt8];
                [elements addObject:@(value)];
                lengthLeft -= 1;
            }
            subpacket.value = [elements copy];
        }
            break;
        case PGPSignatureSubpacketTypeReasonForRevocation:
        {
            // (1 octet of revocability, 0 for not, 1 for revocable)
            UInt8 value = [inputStream readUInt8];
            subpacket.value = @(value);
            lengthLeft -= 1;
        }
            break;
        case PGPSignatureSubpacketTypeIssuerKeyID:
        {
            UInt8 buffer[lengthLeft];
            NSUInteger result = [inputStream read:buffer maxLength:sizeof(buffer)];
            if (result < lengthLeft) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Problem occur with signature subpacket."}];
                }
                return nil;
            }
            lengthLeft -= result;
            subpacket.value = [[PGPKeyID alloc] initWithBytes:buffer length:sizeof(buffer)];
            NSAssert(subpacket.value, @"Invalid value");
        }
            break;
        case PGPSignatureSubpacketTypePrimaryUserID:
        {
            UInt8 buffer[lengthLeft];
            NSUInteger result = [inputStream read:buffer maxLength:sizeof(buffer)];
            if (result != lengthLeft) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Problem occur with signature subpacket."}];
                }
                return nil;
            }
            lengthLeft -= result;
            subpacket.value = [[NSString alloc] initWithBytes:buffer length:sizeof(buffer) encoding:NSUTF8StringEncoding];
            NSAssert(subpacket.value, @"Invalid value");
        }
            break;
        case PGPSignatureSubpacketTypeKeyFlags:
        {
            // (1 octet)
            UInt8 flags = [inputStream readUInt8];
            lengthLeft -= 1;
            
            NSMutableArray *elements = [NSMutableArray array];
            
            if (flags & PGPSignatureFlagAllowCertifyOtherKeys) {
                [elements addObject:@(PGPSignatureFlagAllowCertifyOtherKeys)];
            }
            if (flags & PGPSignatureFlagAllowSignData) {
                [elements addObject:@(PGPSignatureFlagAllowSignData)];
            }
            if (flags & PGPSignatureFlagAllowEncryptCommunications) {
                [elements addObject:@(PGPSignatureFlagAllowEncryptCommunications)];
            }
            if (flags & PGPSignatureFlagAllowEncryptStorage) {
                [elements addObject:@(PGPSignatureFlagAllowEncryptStorage)];
            }
            if (flags & PGPSignatureFlagSecretComponentMayBeSplit) {
                [elements addObject:@(PGPSignatureFlagSecretComponentMayBeSplit)];
            }
            if (flags & PGPSignatureFlagAllowAuthentication) {
                [elements addObject:@(PGPSignatureFlagAllowAuthentication)];
            }
            if (flags & PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons) {
                [elements addObject:@(PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons)];
            }
            subpacket.value = [elements copy];
            NSAssert(elements.count > 0, @"At least one flag is expected");
        }
            break;
        default:
        {
            UInt8 buffer[lengthLeft];
            NSUInteger result = [inputStream read:buffer maxLength:lengthLeft];
            if (result != lengthLeft) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Problem occur with signature subpacket."}];
                }
                return nil;
            }
            lengthLeft -= result;
        }
            break;
    }

    NSAssert(lengthLeft == 0,@"Invalid signature subpacket");
    return subpacket;
}


@end
