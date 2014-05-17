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

#ifdef DEBUG
//TODO: Implement export
- (NSData *) export:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];
    if (self.bodyData) {
        [data appendData:self.headerData];
        [data appendData:self.bodyData];
    } else {
        NSAssert(YES, @"signature export not implemented");
    }
    return [data copy];
}
#endif

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

    // The concatenation of the data being signed and the signature data
    // from the version number through the hashed subpacket data (inclusive) is hashed.
    // The resulting hash value is what is signed.
    self.signedData = [packetBody subdataWithRange:(NSRange){startPosition, position}];

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
    UInt16 leftBits = 0;
    [packetBody getBytes:&leftBits range:(NSRange){position, 2}];
    leftBits = CFSwapInt16BigToHost(leftBits);
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
        subpacketLength   = CFSwapInt16BigToHost(subpacketLength);
        headerLength = 2;
    } else if (lengthOctets[0] == 255) {
        // subpacketLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //                (4th_octet << 8)  | 5th_octet
        subpacketLength   = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8)  | lengthOctets[4];
        subpacketLength   = CFSwapInt32BigToHost(subpacketLength);
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
