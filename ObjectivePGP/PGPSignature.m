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
    // 5.2.4.  Computing Signatures
    NSData *toSignData = buildDataToSign(self.packet.signatureType, self.packet.version, key, user, nil, nil, error);
    NSData *signedPart = [self.packet buildData:error onlySignedPart:YES];
    if (!signedPart || *error) {
        return 0;
    }
    NSData *trailer = [self calculateTrailerFor:signedPart];
    
    NSMutableData *toHash = [NSMutableData data];
    [toHash appendData:toSignData];
    [toHash appendData:signedPart];
    [toHash appendData:trailer];
    
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

@end

// data to produce signature on
NSData *buildDataToSign(PGPSignatureType type, NSUInteger version, PGPKey *key, PGPUser *user, NSData *userAttribute, NSData *data, NSError * __autoreleasing *error)
{
    switch (type) {
        case PGPSignatureBinaryDocument:
        case PGPSignatureCanonicalTextDocument:
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
            [outputData appendData:buildDataToSign(PGPSignatureDirectlyOnKey, version, key, user, userAttribute, data, error)];
            
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
            
            NSMutableData *finalData = [NSMutableData dataWithCapacity:keyData.length + lengthBytes.length];
            [finalData appendData:lengthBytes];
            [finalData appendData:keyData];
            NSData *copy = [finalData copy];
            return copy;
            
        }
        default:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Not implemented, or unknown signature"}];
            }
            break;
    }
    return nil;
}