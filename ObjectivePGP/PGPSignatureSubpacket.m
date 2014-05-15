//
//  PGPSignatureSubPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignatureSubpacket.h"
#import "PGPKeyID.h"

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
        case PGPSignatureSubpacketTypeSignatureCreationTime: // NSDate
        case PGPSignatureSubpacketTypeSignatureExpirationTime:
        case PGPSignatureSubpacketTypeKeyExpirationTime:
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
        case PGPSignatureSubpacketTypeIssuer: // PGPKeyID
        {
            //  5.2.3.5.  Issuer

            PGPKeyID *keyID = [[PGPKeyID alloc] initWithLongKey:packetBody];
            self.value = keyID; //[packetBody subdataWithRange:(NSRange){0,8}];

            /*
            NSMutableString *sbuf = [NSMutableString stringWithCapacity:packetBody.length * 2];
            const unsigned char *buf = packetBody.bytes;
            for (NSUInteger i = 0; i < packetBody.length; ++i) {
                [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
            }
            NSLog(@"%@",sbuf);
             */
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
        case PGPSignatureSubpacketTypeKeyFlags: // NSArray of PGPSignatureFlags
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
        case PGPSignatureSubpacketTypePreferredSymetricAlgorithm: // NSArray of PGPSymmetricAlhorithm
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
        case PGPSignatureSubpacketTypePreferredHashAlgorithm: // NSArray of PGPSymmetricAlhorithm
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
        case PGPSignatureSubpacketTypePreferredCompressionAlgorithm: // NSArray of PGPCompressionAlgorithm
        {
            // 5.2.3.9.  Preferred Compression Algorithms
            // If this subpacket is not included, ZIP is preferred.
            NSMutableArray *algorithmsArray = [NSMutableArray array];

            for (UInt8 i = 0; i < packetBody.length; i++) {
                PGPCompressionAlgorithm algorithm = 0;
                [packetBody getBytes:&algorithm range:(NSRange){i,1}];
                [algorithmsArray addObject:@(algorithm)];
            }

            self.value = [algorithmsArray copy];
        }
            break;
        case PGPSignatureSubpacketTypeKeyServerPreference: // NSArray of PGPKeyServerPreferenceFlags
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
        case PGPSignatureSubpacketTypeFeatures: // NSArray of PGPFeature
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

@end
