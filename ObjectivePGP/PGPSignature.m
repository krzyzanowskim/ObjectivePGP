//
//  PGPSignature.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 30/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignature.h"
#import "PGPKey.h"
#import "PGPFunctions.h"
#import "NSMutableData+PGP.h"
#import "NSData+PGP.h"

@implementation PGPSignature

- (instancetype)initWithPacket:(PGPSignaturePacket *)packet
{
    if (self = [super init]) {
        NSAssert([packet isKindOfClass:[PGPSignaturePacket class]], @"Invalid class");
        _packet = packet;
        _type = packet.signatureType;
        _creationDate = packet.creationDate;
        _issuerKeyID = [packet valueOfSubacketOfType:PGPSignatureSubpacketTypeIssuerKeyID found:nil];
    }
    return self;
}

- (UInt16) computeSignatureHashOverKey:(PGPKey *)key user:(PGPUser *)user error:(NSError * __autoreleasing *)error
{
//    // 5.2.4.  Computing Signatures
    NSData *keyBodyData = [key.packet buildData:error];
    if (!keyBodyData || *error) {
        return 0;
    }
    
    NSMutableData *dataToHash = [NSMutableData data];
    
    if (key) {
        // key old style
        [dataToHash appendData:[NSMutableData dataWithData:buildOldFormatLengthBytesForData(keyBodyData)]];
        [dataToHash appendData:keyBodyData];
    }
    
     if (self.packet.signatureType >= 0x10 && self.packet.signatureType <= 0x13) {
         // A certification signature (type 0x10 through 0x13) hashes the User
         // ID being bound to the key into the hash context after the above
         // data.
         NSData *userData = [user.packet buildData:error];
         [dataToHash appendUInt8:0xB4];
         [dataToHash appendUInt32BE:(UInt32)userData.length];
         [dataToHash appendData:userData];
     }

    // append signed part of signature packet
    switch (self.packet.version) {
        case 0x04:
        {
            // signature signed part
            NSData *signedPart = [self.packet buildData:error onlySignedPart:YES];
            if (!signedPart || *error) {
                return 0;
            }
            [dataToHash appendData:signedPart];
            
            // trailer
            // V4 signatures also hash in a final trailer of six octets: the
            // version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
            // big-endian number that is the length of the hashed data from the
            // Signature packet (note that this number does not include these final six octets).
            NSData *trailer = [self calculateTrailerFor:signedPart];
            [dataToHash appendData:trailer];
            
        }
            break;
            
        default:
            //TODO: 0x03
            NSAssert(false, @"not supported");
            break;
    }

    // calculate hash itself with hash algorithm (for example SHA512)
//    NSData *hash = pgpCalculateSHA512(dataToHash.bytes, (unsigned int)dataToHash.length);
//    UInt16 hashValue = [hash readUInt16BE:(NSRange){0,2}]; // leftmost 16 bits
//    return hashValue;
    
    NSData *toSignData = [PGPSignature toSign:self.packet.signatureType version:self.packet.version key:key user:user userAttribute:nil data:nil error:error];
    NSData *signedPart = [self.packet buildData:error onlySignedPart:YES];
    if (!signedPart || *error) {
        return 0;
    }
    NSData *trailer = [self calculateTrailerFor:signedPart];
    
    NSMutableData *toHash = [NSMutableData data];
    [toHash appendData:toSignData];
    [toHash appendData:signedPart];
    [toHash appendData:trailer];
    
    if ([dataToHash isEqualToData:toHash]) {
        NSLog(@"JEST OK");
    }
    
    NSData *hash = pgpCalculateSHA512(toHash.bytes, (unsigned int)toHash.length);
    UInt16 hashValue = [hash readUInt16BE:(NSRange){0,2}]; // leftmost 16 bits
    return hashValue;
}

- (NSData *) calculateTrailerFor:(NSData *)signedPartData
{
    NSAssert(self.packet.version == 4, @"Not supported signature version");
    if (self.packet.version < 4) {
        NSAssert(false, @"Invalid");
        return nil;
    }
    
    NSMutableData *trailerData = [NSMutableData data];
    UInt8 prefix[2] = {self.packet.version, 0xFF};
    [trailerData appendBytes:&prefix length:2];
    
    [trailerData appendUInt32BE:(UInt32)signedPartData.length];
    return [trailerData copy];
}

// data to produce signature on
+ (NSData *) toSign:(PGPSignatureType)type version:(NSUInteger)version key:(PGPKey *)key user:(PGPUser *)user userAttribute:(NSData *)userAttribute data:(NSData *)data error:(NSError * __autoreleasing *)error
{
    switch (type) {
        case PGPSignatureBinaryDocument:
        case PGPSignatureCanonicalTextDocument:
            NSParameterAssert(data);
            return data;
        case PGPSignatureTimestamp:
        case PGPSignatureStandalone:
            return [NSData data]; // empty
        case PGPSignatureGenericCertificationUserIDandPublicKey:
        case PGPSignaturePersonalCertificationUserIDandPublicKey:
        case PGPSignatureCasualCertificationUserIDandPublicKey:
        case PGPSignaturePositiveCertificationUserIDandPublicKey:
        case PGPSignatureCertificationRevocation:
        {
            NSMutableData *outputData = [NSMutableData data];
            // key
            [outputData appendData:[[self class] toSign:PGPSignatureDirectlyOnKey version:version key:key user:user userAttribute:userAttribute data:data error:error]];
            
            // user
            if (user) {
                NSData *userData = [user.packet buildData:error];
                if (!userData || *error) {
                    return nil;
                }
                if (version == 0x04) {
                    [outputData appendUInt8:0xB4];
                    [outputData appendUInt32BE:(UInt32)userData.length];
                }
                [outputData appendData:userData];
            } else if (userAttribute) {
                if (version == 0x04) {
                    [outputData appendUInt8:0xD1];
                }
                [outputData appendData:userAttribute];
            }
            return [outputData copy];
        }
            break;
        case PGPSignatureKeyRevocation:
        case PGPSignatureDirectlyOnKey:
        {
            NSData *keyData = [key.packet buildData:error];
            NSData *lengthBytes = buildOldFormatLengthBytesForData(keyData);
            NSMutableData *finalData = [NSMutableData data];
            [finalData appendData:lengthBytes];
            [finalData appendData:keyData];
            return [finalData copy];
        }
        default:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Not implemented, or unknown signature"}];
            }
            break;
    }
    return nil;
}

@end
