//
//  PGPSignature.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignaturePacket.h"
#import "PGPMPI.h"
#import "PGPSignatureSubpacket.h"
#import "PGPUserIDPacket.h"
#import "PGPKey.h"
#import "PGPUser.h"
#import "PGPSecretKeyPacket.h"
#import "NSData+PGPUtils.h"

static NSString * const PGPSignatureHeaderSubpacketLengthKey = @"PGPSignatureHeaderSubpacketLengthKey"; // UInt32
static NSString * const PGPSignatureHeaderLengthKey = @"PGPSignatureHeaderLengthKey"; // UInt32
static NSString * const PGPSignatureSubpacketTypeKey = @"PGPSignatureSubpacketTypeKey"; // PGPSignatureSubpacketType


@interface PGPSignaturePacket ()
@property (strong, readwrite, nonatomic) NSMutableArray *hashedSubpackets;
@property (strong, readwrite, nonatomic) NSMutableArray *unhashedSubpackets;
@end

@implementation PGPSignaturePacket

- (NSMutableArray *)hashedSubpackets
{
    if (!_hashedSubpackets) {
        _hashedSubpackets = [NSMutableArray array];
    }
    return _hashedSubpackets;
}

- (NSMutableArray *)unhashedSubpackets
{
    if (!_unhashedSubpackets) {
        _unhashedSubpackets = [NSMutableArray array];
    }
    return _unhashedSubpackets;

}

- (PGPPacketTag)tag
{
    return PGPSignaturePacketTag;
}


- (PGPKeyID *)issuerKeyID
{
    NSArray *subpackets = [self subpackets];

    for (PGPSignatureSubpacket *subpacket in subpackets) {
        if (subpacket.type == PGPSignatureSubpacketTypeIssuer) {
            return subpacket.value;
        }
    }
    return nil;
}

- (NSArray *)subpackets
{
    return [self.hashedSubpackets arrayByAddingObjectsFromArray:self.unhashedSubpackets];
}

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];

    NSData *bodyData = [self buildFullSignatureData:error];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];

    return [data copy];
}

#pragma mark - Build packet

- (NSData *) buildSignedPart
{
    NSMutableData *data = [NSMutableData data];

    // One-octet version number (4).
    UInt8 exportVersion = 4;
    [data appendBytes:&exportVersion length:1];

    // One-octet signature type.
    [data appendBytes:&_type length:sizeof(PGPSignatureType)];

    // One-octet public-key algorithm.
    [data appendBytes:&_publicKeyAlgorithm length:sizeof(PGPPublicKeyAlgorithm)];

    // One-octet hash algorithm.
    [data appendBytes:&_hashAlgoritm length:sizeof(PGPHashAlgorithm)];

    if (self.hashedSubpackets.count > 0) {
        NSMutableData *hashedSubpackets = [NSMutableData data];
        // Hashed subpacket data set (zero or more subpackets)
        for (PGPSignatureSubpacket *subpacket in self.hashedSubpackets) {
            NSError *error = nil;
            NSData *subpacketData = [subpacket exportSubpacket:&error];
            if (subpacketData && !error) {
                [hashedSubpackets appendData:subpacketData];
            }
        }

        // Two-octet scalar octet count for following hashed subpacket data.
        UInt16 hashedOctetCountBE = CFSwapInt16HostToBig(hashedSubpackets.length);
        [data appendBytes:&hashedOctetCountBE length:2];
        // Subpackets
        [data appendData:hashedSubpackets];
    } else {
        UInt16 zeroZero = 0;
        [data appendBytes:&zeroZero length:2];
    }
    
    return [data copy];
}

- (NSData *) buildFullSignatureData:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];

    NSData *signedPartData = [self buildSignedPart];
    [data appendData:signedPartData];

    if (self.unhashedSubpackets.count > 0) {
        NSMutableData *unhashedSubpackets = [NSMutableData data];
        // Hashed subpacket data set (zero or more subpackets)
        for (PGPSignatureSubpacket *subpacket in self.unhashedSubpackets) {
            NSError *error = nil;
            NSData *subpacketData = [subpacket exportSubpacket:&error];
            if (subpacketData && !error) {
                [unhashedSubpackets appendData:subpacketData];
            }
        }
        // Two-octet scalar octet count for following hashed subpacket data.
        UInt16 unhashedOctetCountBE = CFSwapInt16HostToBig(unhashedSubpackets.length);
        [data appendBytes:&unhashedOctetCountBE length:2];
        // Subpackets
        [data appendData:unhashedSubpackets];
    } else {
        UInt16 zeroZero = 0;
        [data appendBytes:&zeroZero length:2];
    }

    [data appendData:self.signedHashValueData];


// MOVE TO SIGN METHOD TO CALCULATE HASH
//    // Two-octet field holding the left 16 bits of the signed hash value.
//    NSData *signedHashData = nil;
//    switch (self.hashAlgoritm) {
//        case PGPHashMD5:
//            signedHashData = [toSignData pgpMD5];
//            break;
//        case PGPHashSHA1:
//            signedHashData = [toSignData pgpSHA1];
//            break;
//        case PGPHashSHA224:
//            signedHashData = [toSignData pgpSHA224];
//            break;
//        case PGPHashSHA256:
//            signedHashData = [toSignData pgpSHA256];
//            break;
//        case PGPHashSHA384:
//            signedHashData = [toSignData pgpSHA384];
//            break;
//        case PGPHashSHA512:
//            signedHashData = [toSignData pgpSHA512];
//            break;
//        case PGPHashRIPEMD160:
//            signedHashData = [toSignData pgpRIPEMD160];
//            break;
//
//        default:
//            break;
//    }
//
//    UInt16 leftBits = 0;
//    [signedHashData getBytes:&leftBits range:(NSRange){0,2}];
//    [data appendBytes:&leftBits length:2];
//    NSLog(@"export leftBits %d",leftBits);

    for (PGPMPI *mpi in self.signatureMPIs) {
        [data appendData:[mpi buildData]];
    }

    return [data copy];
}

//TODO: see https://github.com/singpolyma/openpgp-spec/blob/master/key-signatures
// Produces data to produce signature on
// Produces data to produce signature on
//- (NSData *) sign:(PGPUser *)user key:(PGPKey *)key
//{
//
//    NSMutableData *data = [NSMutableData data];
//    switch (self.type) {
//        case PGPSignaturePersonalCertificationUserIDandPublicKey:
//        case PGPSignatureCasualCertificationUserIDandPublicKey:
//        case PGPSignaturePositiveCertificationUserIDandPublicKey:
//
//        case PGPSignatureGenericCertificationUserIDandPublicKey:
//        case PGPSignatureCertificationRevocation:
//        {
//            // For 0x11, 0x12, 0x13:
//            // The raw fingerprint material for the public-key, followed by the octet 0xB4,
//            // followed by a four-octet number encoding the length of the UserID data,
//            // followed by the raw body of the UserID.
//            // + trailer
////            PGPPublicKeyPacket *primaryKeyPacket = key.primaryKeyPacket;
////
////            [data appendData:primaryKeyPacket.fingerprint.data];
////            if (primaryKeyPacket.keyID) {
////                UInt8 userIDConstant = 0xB4;
////                [data appendBytes:&userIDConstant length:sizeof(userIDConstant)];
////
////                UInt32 userIDLength =
////            }
//
//            //TODO user attributes alternative
//            //UInt8 userAttributeConstant = 0xD1;
//            //[data appendBytes:&userAttributeConstant length:sizeof(userAttributeConstant)];
//        }
//            break;
//
//        default:
//            break;
//    }
//    return nil;
//}

/**
 *  5.2.  Signature Packet (Tag 2)
 *
 *  @param packetBody Packet body
 */
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    NSUInteger startPosition = position;

    // V4
    // One-octet version number (4).
    [packetBody getBytes:&_version range:(NSRange){position,1}];
    position = position + 1;

    //  TODO: Implementations SHOULD accept V3 signatures
    NSAssert(_version == 4, @"Only signature V4 is supported at the moment. Implementations SHOULD accept V3 signatures, but it's not.");
    if (_version != 4) {
        return packetBody.length;
    }

    // One-octet signature type.
    [packetBody getBytes:&_type range:(NSRange){position,1}];
    position = position + 1;

    // One-octet public-key algorithm.
    [packetBody getBytes:&_publicKeyAlgorithm range:(NSRange){position,1}];
    position = position + 1;

    // One-octet hash algorithm.
    [packetBody getBytes:&_hashAlgoritm range:(NSRange){position,1}];
    position = position + 1;

    // Two-octet scalar octet count for following hashed subpacket data.
    UInt16 hashedOctetCount = 0;
    [packetBody getBytes:&hashedOctetCount range:(NSRange){position, 2}];
    hashedOctetCount = CFSwapInt16BigToHost(hashedOctetCount);
    position = position + 2;

    // Hashed subpacket data set (zero or more subpackets)
    // TODO: refactor later, this approach sucks
    NSData *hashedSubpacketsData = nil;
    if (hashedOctetCount > 0) {
        hashedSubpacketsData = [packetBody subdataWithRange:(NSRange){position,hashedOctetCount}];
        position = position + hashedOctetCount;

        NSUInteger positionSubpacket = 0;
        while (positionSubpacket < hashedSubpacketsData.length) {
            PGPSignatureSubpacket *subpacket = [self subpacketAtPosition:positionSubpacket subpacketsData:hashedSubpacketsData];
            [self.hashedSubpackets addObject:subpacket];
            positionSubpacket = subpacket.bodyRange.location + subpacket.bodyRange.length;
        }
    }

    self.signatureData = [packetBody subdataWithRange:(NSRange){startPosition, position}];
    NSLog(@"signatureData %@",self.signatureData);

    // Two-octet scalar octet count for the following unhashed subpacket
    UInt16 unhashedOctetCount = 0;
    [packetBody getBytes:&unhashedOctetCount range:(NSRange){position, 2}];
    unhashedOctetCount = CFSwapInt16BigToHost(unhashedOctetCount);
    position = position + 2;

    // Unhashed subpacket data set (zero or more subpackets)
    NSData *unhashedSubpacketsData = nil;
    if (unhashedOctetCount > 0) {
        unhashedSubpacketsData = [packetBody subdataWithRange:(NSRange){position,unhashedOctetCount}];
        position = position + unhashedOctetCount;

        // Loop subpackets
        NSUInteger positionSubpacket = 0;
        while (positionSubpacket < unhashedSubpacketsData.length) {
            PGPSignatureSubpacket *subpacket = [self subpacketAtPosition:positionSubpacket subpacketsData:unhashedSubpacketsData];
            [self.unhashedSubpackets addObject:subpacket];
            positionSubpacket = subpacket.bodyRange.location + subpacket.bodyRange.length;
        }
    }

    // Two-octet field holding the left 16 bits of the signed hash value.
    self.signedHashValueData = [packetBody subdataWithRange:(NSRange){position, 2}];
    NSLog(@"parse leftBits %@",self.signedHashValueData);
    position = position + 2;


    // 5.2.2. One or more multiprecision integers comprising the signature. This portion is algorithm specific
    // Signature
    switch (_publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA signature value m**d mod n.
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiN.identifier = @"N";
            position = position + mpiN.length;

            self.signatureMPIs = [NSArray arrayWithObject:mpiN];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            PGPMPI *mpiR = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiR.identifier = @"R";
            position = position + mpiR.length;

            // MPI of DSA value s.
            PGPMPI *mpiS = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            mpiS.identifier = @"S";
            position = position + mpiS.length;

            self.signatureMPIs = [NSArray arrayWithObjects:mpiR, mpiS, nil];
        }
            break;
        default:
            break;
    }
    return position;
}

#pragma mark - Private

- (PGPSignatureSubpacket *) subpacketAtPosition:(NSUInteger)subpacketsPosition subpacketsData:(NSData *)subpacketsData
{
    NSRange headerRange = (NSRange) {subpacketsPosition, MIN(6,subpacketsData.length - subpacketsPosition) }; // up to 5+1 octets
    NSData *guessHeaderData = [subpacketsData subdataWithRange:headerRange];

    PGPSignatureSubpacketType subpacketType = 0;
    UInt32 headerLength    = 0;
    UInt32 subpacketLength = 0;

    NSDictionary *subpacketHeaderDictionary = [self parseSubpacketHeader:guessHeaderData];
    [subpacketHeaderDictionary[PGPSignatureSubpacketTypeKey] getValue:&subpacketType];
    [subpacketHeaderDictionary[PGPSignatureHeaderLengthKey] getValue:&headerLength];
    [subpacketHeaderDictionary[PGPSignatureHeaderSubpacketLengthKey] getValue:&subpacketLength];

    NSLog(@"parseSubpacket %@ header %@", @(subpacketType), [subpacketsData subdataWithRange:(NSRange){subpacketsPosition, headerLength}]);
    NSRange bodyRange = (NSRange){subpacketsPosition + headerLength,subpacketLength};
    PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] initWithBody:[subpacketsData subdataWithRange:bodyRange]
                                                                              type:subpacketType];

    subpacket.bodyRange = bodyRange;
    return subpacket;
}

- (NSDictionary *) parseSubpacketHeader:(NSData *)headerData
{
    NSMutableDictionary *configDict = [NSMutableDictionary dictionary];
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

    configDict[PGPSignatureHeaderSubpacketLengthKey] = [[NSValue alloc] initWithBytes:&subpacketLength objCType:@encode(UInt32)];
    configDict[PGPSignatureHeaderLengthKey] = [[NSValue alloc] initWithBytes:&headerLength objCType:@encode(UInt32)];
    configDict[PGPSignatureSubpacketTypeKey] = [[NSValue alloc] initWithBytes:&subpacketType objCType:@encode(PGPSignatureSubpacketType)];

    return [configDict copy];
}

@end
