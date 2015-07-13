//
//  PGPSignatureSubPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignatureSubpacket.h"
#import "PGPKeyID.h"
#import "PGPPacket.h"
#import "PGPCompressedPacket.h"
#import "NSValue+PGPUtils.h"

@implementation PGPSignatureSubpacketHeader
@end

@interface PGPSignatureSubpacket ()
@property (strong, readwrite) id value;
@end

@implementation PGPSignatureSubpacket

- (instancetype) initWithHeader:(PGPSignatureSubpacketHeader *)header body:(NSData *)subPacketBodyData bodyRange:(NSRange)bodyRange
{
    if (self = [self init]) {
        _type = header.type;
        _bodyRange = bodyRange;
        [self parseSubpacketBody:subPacketBodyData];
    }
    return self;
}

+ (PGPSignatureSubpacket *) subpacketWithType:(PGPSignatureSubpacketType)type andValue:(id)value
{
    PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] init];
    subpacket.type = type;
    subpacket.value = value;
    return subpacket;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %d %@", [super description], self.type, self.value];
}

/**
 *  5.2.3.1.  Signature Subpacket Specification
 *
 *  @param packetBody A single subpacket body data.
 */
- (void) parseSubpacketBody:(NSData *)packetBody
{
    // NSLog(@"parseSubpacket %@, body %@",@(self.type), packetBody);
    switch (self.type) {
        case PGPSignatureSubpacketTypeSignatureCreationTime: // NSDate
        {
            //  5.2.3.4.  Signature Creation Time
            //  Signature Creation Time MUST be present in the hashed area.

            UInt32 signatureCreationTimestamp = 0;
            [packetBody getBytes:&signatureCreationTimestamp length:4];
            signatureCreationTimestamp = CFSwapInt32BigToHost(signatureCreationTimestamp);
            self.value = [NSDate dateWithTimeIntervalSince1970:signatureCreationTimestamp];
        }
            break;
        case PGPSignatureSubpacketTypeSignatureExpirationTime: // NSNumber
        case PGPSignatureSubpacketTypeKeyExpirationTime:
        {
            //  5.2.3.10. Signature Expiration Time
            //  5.2.3.6.  Key Expiration Time
            //   The validity period of the signature
            UInt32 validityPeriodTime = 0;
            [packetBody getBytes:&validityPeriodTime length:4];
            validityPeriodTime = CFSwapInt32BigToHost(validityPeriodTime);
            self.value = @(validityPeriodTime);

        }
            break;
        case PGPSignatureSubpacketTypeTrustSignature:
        {
            // (1 octet "level" (depth), 1 octet of trust amount)
            // TODO trust subpacket
        }
            break;
        case PGPSignatureSubpacketTypeIssuerKeyID: // PGPKeyID
        {
            //  5.2.3.5.  Issuer

            PGPKeyID *keyID = [[PGPKeyID alloc] initWithLongKey:packetBody];
            self.value = keyID; //[packetBody subdataWithRange:(NSRange){0,8}];
        }
            break;
        case PGPSignatureSubpacketTypeExportableCertification:  // NSNumber BOOL
        {
            // 5.2.3.11.  Exportable Certification
            UInt8 exportableValue = 0;
            [packetBody getBytes:&exportableValue length:1];
            self.value = @(exportableValue);
        }
            break;
        case PGPSignatureSubpacketTypePrimaryUserID:            // NSNumber BOOL
        {
            // 5.2.3.19.  Primary User ID
            UInt8 primaryUserIDValue = 0;
            [packetBody getBytes:&primaryUserIDValue length:1];
            self.value = @(primaryUserIDValue);
        }
            break;
        case PGPSignatureSubpacketTypeSignerUserID:         // NSString
            // side note: This subpacket is not appropriate to use to refer to a User Attribute packet.
        case PGPSignatureSubpacketTypePreferredKeyServer:   // NSString
        case PGPSignatureSubpacketTypePolicyURI:            // NSString
        {
            self.value = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
        }
            break;
        case PGPSignatureSubpacketTypeReasonForRevocation:  // NSNumber
        {
            UInt8 revocationCode = 0;
            [packetBody getBytes:&revocationCode length:1];
            self.value = @(revocationCode);
        }
            break;
        case PGPSignatureSubpacketTypeKeyFlags: // NSArray of NSNumber
        {
            //  5.2.3.21.  Key Flags
            //  (N octets of flags) ???
            //  This implementation supports max 8 octets (64bit)
            UInt64 flagByte = 0;
            [packetBody getBytes:&flagByte length:MIN(8,packetBody.length)];
            NSMutableArray *flagsArray = [NSMutableArray array];

            if (flagByte & PGPSignatureFlagAllowCertifyOtherKeys) {
                [flagsArray addObject:@(PGPSignatureFlagAllowCertifyOtherKeys)];
            }
            if (flagByte & PGPSignatureFlagAllowSignData) {
                [flagsArray addObject:@(PGPSignatureFlagAllowSignData)];
            }
            if (flagByte & PGPSignatureFlagAllowEncryptCommunications) {
                [flagsArray addObject:@(PGPSignatureFlagAllowEncryptCommunications)];
            }
            if (flagByte & PGPSignatureFlagAllowEncryptStorage) {
                [flagsArray addObject:@(PGPSignatureFlagAllowEncryptStorage)];
            }
            if (flagByte & PGPSignatureFlagSecretComponentMayBeSplit) {
                [flagsArray addObject:@(PGPSignatureFlagSecretComponentMayBeSplit)];
            }
            if (flagByte & PGPSignatureFlagAllowAuthentication) {
                [flagsArray addObject:@(PGPSignatureFlagAllowAuthentication)];
            }
            if (flagByte & PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons) {
                [flagsArray addObject:@(PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons)];
            }

            self.value = [flagsArray copy];
        }
            break;
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm: // NSArray of NSValue @encode(PGPSymmetricAlgorithm)
        {
            // 5.2.3.7.  Preferred Symmetric Algorithms
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (NSUInteger i = 0; i < packetBody.length; i++) {
                PGPSymmetricAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];

                NSValue *val = [NSValue valueWithBytes:&algorithm objCType:@encode(PGPSymmetricAlgorithm)];
                [algorithmsArray addObject:val];
            }

            self.value = [algorithmsArray copy];
        }
            break;
        case PGPSignatureSubpacketTypePreferredHashAlgorithm: // NSArray of NSValue @encode(PGPHashAlgorithm)
        {
            // 5.2.3.8.  Preferred Hash Algorithms
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (NSUInteger i = 0; i < packetBody.length; i++) {
                PGPHashAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];

                NSValue *val = [NSValue valueWithBytes:&algorithm objCType:@encode(PGPHashAlgorithm)];
                [algorithmsArray addObject:val];
            }

            self.value = [algorithmsArray copy];
        }
            break;
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm: // NSArray of NSValue @encode(PGPCompressionAlgorithm)
        {
            // 5.2.3.9.  Preferred Compression Algorithms
            // If this subpacket is not included, ZIP is preferred.
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (UInt8 i = 0; i < packetBody.length; i++) {
                PGPCompressionAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];

                NSValue *val = [NSValue valueWithBytes:&algorithm objCType:@encode(PGPCompressionAlgorithm)];
                [algorithmsArray addObject:val];
            }

            self.value = [algorithmsArray copy];
        }
            break;
        case PGPSignatureSubpacketTypeKeyServerPreference: // NSArray of NSNumber PGPKeyServerPreferenceFlags
        {
            // 5.2.3.17.  Key Server Preferences
            PGPKeyServerPreferenceFlags flag = 0;
            [packetBody getBytes:&flag length:MIN(8,packetBody.length)];

            NSMutableArray *flagsArray = [NSMutableArray array];
            if (flag & PGPKeyServerPreferenceNoModify) {
                [flagsArray addObject:@(PGPKeyServerPreferenceNoModify)];
            }
            self.value = [flagsArray copy];
        }
            break;
        case PGPSignatureSubpacketTypeFeatures: // NSArray of NSNumber PGPFeature
        {
            // 5.2.3.24.  Features
            NSMutableArray *featuresArray = [NSMutableArray array];

            for (NSUInteger i = 0; i < packetBody.length; i++) {
                PGPFeature feature = 0;
                [packetBody getBytes:&feature range:(NSRange){i,1}];
                [featuresArray addObject:@(feature)];
            }

            self.value = [featuresArray copy];
        }
            break;
        default:
#ifdef DEBUG
            NSLog(@"Unsuported subpacket type %d", self.type);
#endif
            break;
    }
}

- (NSData *) exportSubpacket:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];

    // subpacket type
    PGPSignatureSubpacketType type = self.type;
    [data appendBytes:&type length:1];

    switch (self.type) {
        case PGPSignatureSubpacketTypeSignatureCreationTime: // NSDate
        {
            NSDate *date = (NSDate *)self.value;
            UInt32 signatureCreationTimestamp = CFSwapInt32HostToBig((UInt32)[date timeIntervalSince1970]);
            [data appendBytes:&signatureCreationTimestamp length:4];
        }
            break;
        case PGPSignatureSubpacketTypeSignatureExpirationTime: // NSNumber
        case PGPSignatureSubpacketTypeKeyExpirationTime:
        {
            NSNumber *validityPeriod = (NSNumber *)self.value;
            UInt32 validityPeriodInt = CFSwapInt32HostToBig((UInt32)validityPeriod.unsignedIntegerValue);
            [data appendBytes:&validityPeriodInt length:4];
        }
            break;
        case PGPSignatureSubpacketTypeIssuerKeyID: // PGPKeyID
        {
            PGPKeyID *keyID = self.value;
            [data appendData:[keyID exportKeyData]];
        }
            break;
        case PGPSignatureSubpacketTypeExportableCertification:  // NSNumber BOOL
        case PGPSignatureSubpacketTypePrimaryUserID:            // NSNumber BOOL
        {
            NSNumber *boolNumber = self.value;
            BOOL boolValue = [boolNumber boolValue];
            [data appendBytes:&boolValue length:1];
        }
            break;
        case PGPSignatureSubpacketTypeSignerUserID:         // NSString
        case PGPSignatureSubpacketTypePreferredKeyServer:   // NSString
        case PGPSignatureSubpacketTypePolicyURI:            // NSString
        {
            NSString *stringValue = self.value;
            [data appendData:[stringValue dataUsingEncoding:NSUTF8StringEncoding]];
        }
            break;
        case PGPSignatureSubpacketTypeReasonForRevocation:
        {
            // 5.2.3.23.  Reason for Revocation
            NSNumber *revocationCode = self.value;
            UInt8 revocationCodeByte = [revocationCode unsignedIntValue];
            [data appendBytes:&revocationCodeByte length:1];
        }
            break;
        case PGPSignatureSubpacketTypeKeyFlags: // NSArray of NSNumber PGPSignatureFlags
        {
            //TODO: actually it can be more than one byte (documented)
            //      so I should calculate how many bytes do I need here
            NSArray *flagsArray = self.value;
            PGPSignatureFlags flagByte = 0;
            for (NSNumber *flagByteNumber in flagsArray) {
                flagByte = flagByte | ((UInt8)[flagByteNumber unsignedIntValue]);
            }
            [data appendBytes:&flagByte length:sizeof(PGPSignatureFlags)];
        }
            break;
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm: // NSArray of NSValue @encode(PGPSymmetricAlgorithm)
        {
            NSArray *algorithmsArray = self.value;
            for (NSValue *val in algorithmsArray) {
                if (![val pgp_objCTypeIsEqualTo:@encode(PGPSymmetricAlgorithm)]) {
                    continue;
                }

                PGPSymmetricAlgorithm symmetricAlgorithm = 0;
                [val getValue:&symmetricAlgorithm];

                [data appendBytes:&symmetricAlgorithm length:sizeof(PGPSymmetricAlgorithm)];
            }
        }
            break;
        case PGPSignatureSubpacketTypePreferredHashAlgorithm: // NSArray of of NSValue @encode(PGPHashAlgorithm)
        {
            NSArray *algorithmsArray = self.value;
            for (NSValue *val in algorithmsArray) {
                if (![val pgp_objCTypeIsEqualTo:@encode(PGPHashAlgorithm)]) {
                    continue;
                }

                PGPHashAlgorithm hashAlgorithm = 0;
                [val getValue:&hashAlgorithm];
                [data appendBytes:&hashAlgorithm length:sizeof(PGPHashAlgorithm)];
            }
        }
            break;
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm: // NSArray of NSValue @encode(PGPCompressionAlgorithm)
        {
            NSArray *algorithmsArray = self.value;
            for (NSValue *val in algorithmsArray) {
                if (![val pgp_objCTypeIsEqualTo:@encode(PGPCompressionAlgorithm)]) {
                    continue;
                }

                PGPCompressionAlgorithm hashAlgorithm = 0;
                [val getValue:&hashAlgorithm];
                [data appendBytes:&hashAlgorithm length:sizeof(PGPCompressionAlgorithm)];
            }
        }
            break;
        case PGPSignatureSubpacketTypeKeyServerPreference: // NSArray of NSNumber PGPKeyServerPreferenceFlags
        {
            //TODO: actually it can be more than one byte (documented)
            //      so I should calculate how many bytes do I need here
            PGPKeyServerPreferenceFlags allFlags = 0;
            NSArray *flagsArray = (NSArray *)self.value;
            for (NSNumber *flagNumber in flagsArray) {
                PGPKeyServerPreferenceFlags flag = (PGPKeyServerPreferenceFlags)flagNumber.unsignedIntValue;
                allFlags = allFlags | flag;
            }
            [data appendBytes:&allFlags length:sizeof(PGPKeyServerPreferenceFlags)];
        }
            break;
        case PGPSignatureSubpacketTypeFeatures: // NSArray of NSNumber PGPFeature
        {
            //TODO: actually it can be more than one byte (documented)
            //      so I should calculate how many bytes do I need here
            NSArray *flagsArray = self.value;
            PGPFeature flagByte = 0;
            for (NSNumber *flagByteNumber in flagsArray) {
                flagByte = flagByte | ((UInt8)[flagByteNumber unsignedIntValue]);
            }
            [data appendBytes:&flagByte length:sizeof(PGPSignatureFlags)];
        }
            break;
        default:
#ifdef DEBUG
            NSLog(@"Unsuported subpacket type %d", self.type);
#endif
            break;
    }

    //subpacket = length + tag + body
    NSMutableData *subpacketData = [NSMutableData data];
    // the subpacket length (1, 2, or 5 octets),
    NSData *subpacketLengthData = [PGPPacket buildNewFormatLengthDataForData:data];
    [subpacketData appendData:subpacketLengthData]; // data with tag
    [subpacketData appendData:data];

    // NSLog(@"exportSubpacket %@, header  %@",@(self.type), [subpacketData subdataWithRange:(NSRange){0, subpacketLengthData.length + 1}]);
    // NSLog(@"exportSubpacket %@, body  %@",@(self.type), [data subdataWithRange:(NSRange){1,data.length - 1}]);

    return [subpacketData copy];
}

+ (PGPSignatureSubpacketHeader *) subpacketHeaderFromData:(NSData *)headerData
{
    NSUInteger position = 0;

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(position, MIN(5,headerData.length))].bytes;
    UInt32 headerLength = 0;
    UInt32 subpacketLength = 0;

    if (lengthOctets[0] < 192) {
        // subpacketLen = 1st_octet;
        subpacketLength = lengthOctets[0];
        headerLength = 1 ;
    } else if (lengthOctets[0] >= 192 && lengthOctets[0] < 255) {
        // subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        subpacketLength   = ((lengthOctets[0] - 192) << 8) + (lengthOctets[1]) + 192;
        headerLength = 2;
    } else if (lengthOctets[0] == 255) {
        // subpacketLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //                (4th_octet << 8)  | 5th_octet
        subpacketLength   = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8)  | lengthOctets[4];
        headerLength = 5;
    }
    position = position + headerLength;

    //TODO: Bit 7 of the subpacket type is the "critical" bit.
    PGPSignatureSubpacketType subpacketType = 0;
    [headerData getBytes:&subpacketType range:(NSRange){position, 1}];
    headerLength = headerLength + 1;

    // Note: "The length includes the type octet but not this length"
    // Example: 02 19 01
    // length 0x02 = 2
    // type 0x19   = 25
    // body: 0x01  = 1
    // so... given body length is = 2 but body length is in fact = 1
    // this is because given body length include type octet which is from header namespace, not body really.
    // I'm drunk, or person who defined it this way was drunk.
    subpacketLength = subpacketLength - 1;

    PGPSignatureSubpacketHeader *subpacketHeader = [[PGPSignatureSubpacketHeader alloc] init];
    subpacketHeader.type = subpacketType;
    subpacketHeader.headerLength = headerLength;
    subpacketHeader.bodyLength = subpacketLength;

    return subpacketHeader;
}


@end
