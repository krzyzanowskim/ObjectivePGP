//
//  PGPSignatureSubPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignatureSubpacket.h"

@interface PGPSignatureSubpacket ()
@property (strong, readwrite) id value;
@end

@implementation PGPSignatureSubpacket

- (instancetype) initWithBody:(NSData *)packetBody type:(PGPSignatureSubpacketType)type
{
    if (self = [self init]) {
        self->_type = type;
        [self parseSubpacketBody:packetBody];
#ifdef DEBUG
        NSLog(@"subpacket type %@", @(self.type));
#endif
    }
    return self;
}

/**
 *  5.2.3.1.  Signature Subpacket Specification
 *
 *  @param packetBody A single subpacket body data.
 */
- (void) parseSubpacketBody:(NSData *)packetBody
{
    switch (self.type) {
        case PGPSignatureSubpacketSignatureCreationTime: // NSDate
        case PGPSignatureSubpacketSignatureExpirationTime:
        case PGPSignatureSubpacketKeyExpirationTime:
        {
            //  5.2.3.4.  Signature Creation Time
            //  5.2.3.10. Signature Expiration Time
            //  5.2.3.6.  Key Expiration Time
            //TODO: Signature Creation Time MUST be present in the hashed area.

            UInt32 signatureCreationTimestamp = 0;
            [packetBody getBytes:&signatureCreationTimestamp length:4];
            signatureCreationTimestamp = CFSwapInt32BigToHost(signatureCreationTimestamp);
            self.value = [NSDate dateWithTimeIntervalSince1970:signatureCreationTimestamp];

        }
            break;
        case PGPSignatureSubpacketIssuer: // NSData
        {
            //  5.2.3.5.  Issuer
            //TODO: wtf actually? see 12.2.  Key IDs and Fingerprints
            self.value = [packetBody subdataWithRange:(NSRange){0,8}];
        }
            break;
        case PGPSignatureSubpacketPrimaryUserID: // NSNumber BOOL
        {
            // 5.2.3.19.  Primary User ID
            UInt8 primaryUserIDValue = 0;
            [packetBody getBytes:&primaryUserIDValue length:1];
            self.value = @(primaryUserIDValue);
        }
            break;
        case PGPSignatureSubpacketKeyFlags: // NSArray of PGPSignatureFlags
        {
            //  5.2.3.21.  Key Flags
            //  (N octets of flags) ???
            //  This implementation supports max 8 octets (64bit)
            UInt64 flagByte = 0;
            [packetBody getBytes:&flagByte length:MIN(8,packetBody.length)];
            NSMutableArray *flagsArray = [NSMutableArray array];

            if (flagByte & PGPSignatureFlagAllowCertifyOtherKeys) {
                [flagsArray addObject:@(PGPSignatureFlagAllowCertifyOtherKeys)];
            } else if (flagByte & PGPSignatureFlagAllowSignData) {
                [flagsArray addObject:@(PGPSignatureFlagAllowSignData)];
            } else if (flagByte & PGPSignatureFlagAllowEncryptCommunications) {
                [flagsArray addObject:@(PGPSignatureFlagAllowEncryptCommunications)];
            } else if (flagByte & PGPSignatureFlagAllowEncryptStorage) {
                [flagsArray addObject:@(PGPSignatureFlagAllowEncryptStorage)];
            } else if (flagByte & PGPSignatureFlagSecretComponentMayBeSplit) {
                [flagsArray addObject:@(PGPSignatureFlagSecretComponentMayBeSplit)];
            } else if (flagByte & PGPSignatureFlagAllowAuthentication) {
                [flagsArray addObject:@(PGPSignatureFlagAllowAuthentication)];
            } else if (flagByte & PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons) {
                [flagsArray addObject:@(PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons)];
            }

            self.value = [flagsArray copy];
        }
            break;
        case PGPSignatureSubpacketPreferredSymetricAlgorithm: // NSArray of PGPSymmetricAlhorithm
        {
            // 5.2.3.7.  Preferred Symmetric Algorithms
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (NSUInteger i = 0; i < packetBody.length; i++) {
                PGPSymmetricAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];
                [algorithmsArray addObject:@(algorithm)];
            }

            self.value = [algorithmsArray copy];
        }
            break;
        case PGPSignatureSubpacketPreferredHashAlgorithm: // NSArray of PGPSymmetricAlhorithm
        {
            // 5.2.3.8.  Preferred Hash Algorithms
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (NSUInteger i = 0; i < packetBody.length; i++) {
                PGPHashAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];
                [algorithmsArray addObject:@(algorithm)];
            }

            self.value = [algorithmsArray copy];
        }
            break;
        case PGPSignatureSubpacketPreferredCompressionAlgorithm: // NSArray of PGPCompressionAlgorithm
        {
            // 5.2.3.9.  Preferred Compression Algorithms
            // If this subpacket is not included, ZIP is preferred.
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (UInt8 i = 0; i < packetBody.length; i++) {
                PGPCompressionAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];
                [algorithmsArray addObject:@(algorithm)];
            }

            self.value = [algorithmsArray copy];        }
            break;
        case PGPSignatureSubpacketKeyServerPreference:
        {
            // 5.2.3.17.  Key Server Preferences
            UInt64 flagByte = 0;
            [packetBody getBytes:&flagByte length:MIN(8,packetBody.length)];
            NSMutableArray *flagsArray = [NSMutableArray array];
            if (flagByte & PGPKeyServerPreferenceNoModify) {
                [flagsArray addObject:@(PGPKeyServerPreferenceNoModify)];
            }
            self.value = [flagsArray copy];
        }
            break;
        case PGPSignatureSubpacketFeatures:
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
            NSLog(@"Unsuported subpacket type %d", self.type);
            break;
    }
}

+ (PGPSignatureSubpacketType) parseSubpacketHeader:(NSData *)headerData headerLength:(UInt32 *)headerLength subpacketLength:(UInt32 *)subpacketLen
{
    NSUInteger position     = 0;

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(position, MIN(5,headerData.length))].bytes;

    UInt8 firstOctet  = lengthOctets[0];
    UInt8 secondOctet = lengthOctets[1];
    UInt8 thirdOctet  = lengthOctets[2];
    UInt8 fourthOctet = lengthOctets[3];
    UInt8 fifthOctet  = lengthOctets[4];

    if (firstOctet < 192) {
        // subpacketLen = 1st_octet;
        *subpacketLen   = firstOctet;
        *headerLength = 1 ;
    } else if (firstOctet >= 192 && firstOctet < 255) {
        // subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        *subpacketLen   = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        *subpacketLen   = CFSwapInt16BigToHost(*subpacketLen);
        *headerLength = 2;
    } else if (firstOctet == 255) {
        // subpacketLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //                (4th_octet << 8)  | 5th_octet
        *subpacketLen   = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet;
        *subpacketLen   = CFSwapInt32BigToHost(*subpacketLen);
        *headerLength = 5;
    }
    position = position + *headerLength;

    //TODO: Bit 7 of the subpacket type is the "critical" bit.
    PGPSignatureSubpacketType subpacketType = 0;
    [headerData getBytes:&subpacketType range:(NSRange){position, 1}];
    *headerLength = *headerLength + 1;

    // Note: "The length includes the type octet but not this length"
    // Example: 02 19 01
    // length 0x02 = 2
    // type 0x19   = 25
    // body: 0x01  = 1
    // so... given body length is = 2 but body length is in fact = 1
    // this is because given body length include type octet which is from header namespace, not body really.
    // I'm drunk, or person who defined it this way was drunk.
    *subpacketLen = *subpacketLen - 1;
    
    return subpacketType;
}

@end
