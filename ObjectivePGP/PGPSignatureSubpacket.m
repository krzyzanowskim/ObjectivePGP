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
#import "NSOutputStream+PGP.h"
#import "PGPKeyID.h"
#import "PGPSignaturePacket.h"
#import "PGPPacketHeader.h"
#import "PGPFunctions.h"
#import "NSMutableData+PGP.h"

@interface PGPSignatureSubpacket ()
@end

@implementation PGPSignatureSubpacket

+ (instancetype) readFromStream:(NSInputStream *)inputStream data:(NSData * __autoreleasing *)readData error:(NSError * __autoreleasing *)error
{
    PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] init];
    NSMutableData *rawData = [NSMutableData data];
    
    // the subpacket length (1, 2, or 5 octets)
    // Note: "The length includes the type octet but not this length"
    // Example: 02 19 01
    // length 0x02 = 2
    // type 0x19   = 25
    // body: 0x01  = 1
    // so... given body length is = 2 but body length is in fact = 1
    // this is because given body length include type octet which is from header namespace, not body really.
    // I'm drunk, or person who defined it this way was drunk.
    
    UInt8 firstOctet = [inputStream readUInt8BytesAppendTo:rawData];
    NSUInteger length = 0;
    NSUInteger lengthOfLength = 0;
    if (firstOctet < 192) {
        length  = firstOctet;
        lengthOfLength = 1;
    } else if (firstOctet >= 192 && firstOctet < 255) {
        UInt8 secondOctet = [inputStream readUInt8BytesAppendTo:rawData];
        length   = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        lengthOfLength = 2;
    } else if (firstOctet == 255) {
        length  = [inputStream readUInt32BytesAppendTo:rawData];
        lengthOfLength = 5;
    }
    subpacket.totalLength = length + lengthOfLength;
    NSUInteger lengthLeft = length;

    // the subpacket type (1 octet),
    subpacket.type = [inputStream readUInt8BytesAppendTo:rawData];
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
        case PGPSignatureSubpacketTypeKeyExpirationTime:
        {
            // (4 octets) The time the signature was made.
            UInt32 timestamp = [inputStream readUInt32BE];
            [rawData appendUInt32BE:timestamp];
            subpacket.value = [NSDate dateWithTimeIntervalSince1970:timestamp];;
            lengthLeft -= 4;
        }
            break;
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm:
        case PGPSignatureSubpacketTypePreferredHashAlgorithm:
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm:
        case PGPSignatureSubpacketTypeFeatures:
        {
            NSMutableArray *elements = [NSMutableArray array];
            while (lengthLeft) {
                UInt8 value = [inputStream readUInt8];
                [rawData appendUInt8:value];
                [elements addObject:@(value)];
                lengthLeft -= 1;
            }
            subpacket.value = [elements copy];
        }
            break;
//        case PGPSignatureSubpacketTypeRegularExpression:
//        {
//            //TODO: this feature is not supported
//            // (null-terminated regular expression)
//            UInt8 buffer[lengthLeft];
//            NSUInteger result = [inputStream read:buffer maxLength:sizeof(buffer)];
//            if (result < lengthLeft) {
//                if (error) {
//                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Problem occur with signature subpacket."}];
//                }
//                return nil;
//            }
//            lengthLeft -= result;
//            subpacket.value = [[NSString alloc] initWithBytes:buffer length:sizeof(buffer) encoding:NSUTF8StringEncoding];
//            [rawData appendBytes:buffer length:sizeof(buffer)];
//            NSAssert(subpacket.value, @"Invalid value");
//        }
//        break;
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
            [rawData appendBytes:buffer length:sizeof(buffer)];
            NSAssert(subpacket.value, @"Invalid value");
        }
            break;
        case PGPSignatureSubpacketTypeTrustSignature:
        {
            // (1 octet of revocability, 0 for not, 1 for revocable)
            UInt8 value = [inputStream readUInt8];
            [rawData appendUInt8:value];
            subpacket.value = @(value);
            lengthLeft -= 1;
        }
            break;
        case PGPSignatureSubpacketTypeRevocable:
        case PGPSignatureSubpacketTypeExportableCertification:
        case PGPSignatureSubpacketTypePrimaryUserID:
        {
            UInt8 value = [inputStream readUInt8];
            NSAssert(value < 2, @"Invalid bool value");
            [rawData appendUInt8:value];
            lengthLeft -= 1;
            subpacket.value = @((BOOL)value);
        }
            break;
        case PGPSignatureSubpacketTypeSignerUserID:
        case PGPSignatureSubpacketTypePreferredKeyServer:
        case PGPSignatureSubpacketTypePolicyURI:
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
            [rawData appendBytes:buffer length:sizeof(buffer)];
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
            [rawData appendUInt8:flags];
            subpacket.value = [elements copy];
            NSAssert(elements.count > 0, @"At least one flag is expected");
        }
            break;
        case PGPSignatureSubpacketTypeKeyServerPreference:
        {
            UInt8 flags = [inputStream readUInt8];
            lengthLeft -= 1;
            NSMutableArray *elements = [NSMutableArray array];
            if (flags & PGPKeyServerPreferenceNoModify) {
                [elements addObject:@(PGPKeyServerPreferenceNoModify)];
            }
            [rawData appendUInt8:flags];
            subpacket.value = [elements copy];
        }
            break;
        case PGPSignatureSubpacketTypeRegularExpression: //TODO: This feature is not supported
        case PGPSignatureSubpacketTypeReasonForRevocation:
        case PGPSignatureSubpacketTypeRevocationKey: //TODO: (1 octet of class, 1 octet of public-key algorithm ID, 20 octets of fingerprint)
        case PGPSignatureSubpacketTypeSignatureTarget: //TODO
        case PGPSignatureSubpacketTypeNotationData:
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
            [rawData appendBytes:buffer length:result];
            subpacket.value = [NSData dataWithBytes:buffer length:result];
        }
            break;
        default:
            NSAssert(false, @"Not handled");
            break;
    }

    NSAssert(lengthLeft == 0,@"Invalid signature subpacket");
    if (lengthLeft != 0) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid signature subpacket."}];
        }
        return nil;
    }

    if (readData) {
        *readData = [rawData copy];
    }
    
    return subpacket;
}

- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError *__autoreleasing *)error
{
    NSMutableData *bodyData = [NSMutableData dataWithCapacity:self.totalLength];
    if (self.critical) {
        //TODO: remove critical bit and update type
    }
    [bodyData appendUInt8:self.type];
    
    // new format length
    switch (self.type) {
        case PGPSignatureSubpacketTypeSignatureCreationTime:
        case PGPSignatureSubpacketTypeSignatureExpirationTime:
        case PGPSignatureSubpacketTypeKeyExpirationTime:
        {
            NSAssert([self.value isKindOfClass:[NSDate class]], @"Invalid value");
            NSDate *date = (NSDate *)self.value;
            [bodyData appendUInt32BE:[date timeIntervalSince1970]];
        }
        break;
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm:
        case PGPSignatureSubpacketTypePreferredHashAlgorithm:
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm:
        case PGPSignatureSubpacketTypeFeatures:
        {
            NSAssert([self.value isKindOfClass:[NSArray class]], @"Invalid value");
            NSArray *elements = (NSArray *)self.value;
            for (NSNumber *number in elements) {
                [bodyData appendUInt8:number.unsignedShortValue];
            }
        }
        break;
        case PGPSignatureSubpacketTypeSignerUserID:
        case PGPSignatureSubpacketTypePreferredKeyServer:
        case PGPSignatureSubpacketTypePolicyURI:
        {
            NSAssert([self.value isKindOfClass:[NSString class]], @"Invalid value");
            NSString *value = (NSString *)self.value;
            [bodyData appendData:[value dataUsingEncoding:NSUTF8StringEncoding]];
        }
        break;
        case PGPSignatureSubpacketTypeIssuerKeyID:
        {
            NSAssert([self.value isKindOfClass:[PGPKeyID class]], @"Invalid value");
            PGPKeyID *keyID = self.value;
            [bodyData appendData:[keyID octetsData]];
        }
        break;
        case PGPSignatureSubpacketTypeTrustSignature:
        {
            // 1 octet
            NSAssert([self.value isKindOfClass:[NSNumber class]], @"Invalid value");
            NSNumber *number = (NSNumber *)self.value;
            [bodyData appendUInt8:number.unsignedShortValue];
        }
            break;
        case PGPSignatureSubpacketTypeRevocable:
        case PGPSignatureSubpacketTypeExportableCertification:
        case PGPSignatureSubpacketTypePrimaryUserID:
        {
            NSAssert([self.value isKindOfClass:[NSNumber class]], @"Invalid value");
            NSNumber *value = (NSNumber *)self.value;
            NSAssert(value.unsignedShortValue > 1, @"Invalid value");
            [bodyData appendUInt8:(UInt8)value.unsignedShortValue];
        }
        break;
        case PGPSignatureSubpacketTypeKeyFlags:
        case PGPSignatureSubpacketTypeKeyServerPreference:
        {
            NSAssert([self.value isKindOfClass:[NSArray class]], @"Invalid value");
            NSArray *elements = (NSArray *)self.value;
            UInt8 flags = 0;
            for (NSNumber *flag in elements) {
                flags = flags | (UInt8)flag.unsignedShortValue;
            }
            [bodyData appendUInt8:flags];
        }
        break;
        case PGPSignatureSubpacketTypeRegularExpression: //TODO: this feature is not supported
        case PGPSignatureSubpacketTypeReasonForRevocation:
        case PGPSignatureSubpacketTypeRevocationKey:
        case PGPSignatureSubpacketTypeSignatureTarget:
        case PGPSignatureSubpacketTypeNotationData:
        {
            //NSData raw data
            NSAssert([self.value isKindOfClass:[NSData class]], @"Invalid raw data");
            NSData *value = (NSData *)self.value;
            [bodyData appendData:value];
        }
            break;
        default:
            NSAssert(false, @"Not handled");
            break;
    }
    
    NSData *lengthData = buildNewFormatLengthBytesForData(bodyData);
    [bodyData appendData:lengthData];
    [bodyData appendData:bodyData];
    return [outputStream writeData:lengthData];
}


@end
