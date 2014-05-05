//
//  PGPSignature.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignaturePacket.h"
#import "PGPMPI.h"
#import "PGPSignatureSubpacket.h"

@interface PGPSignaturePacket ()
@property (strong, readwrite, nonatomic) NSMutableArray *hashedSubpackets;
@property (strong, readwrite, nonatomic) NSMutableArray *unhashedSubpackets;
@end

@implementation PGPSignaturePacket

- (instancetype) initWithBody:(NSData *)packetData
{
    if (self = [self init]) {
        [self parsePacketBody:packetData];
    }
    return self;
}

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

/**
 *  5.2.  Signature Packet (Tag 2)
 *
 *  @param packetBody Packet body
 */
- (void)parsePacketBody:(NSData *)packetBody
{
    //  TODO: Implementations SHOULD accept V3 signatures

    // V4
    NSUInteger position = 0;
    // One-octet version number (4).
    [packetBody getBytes:&_version range:(NSRange){position,1}];
    position = position + 1;

    NSAssert(_version == 4, @"Only signature V4 is supported");

    // One-octet signature type.
    [packetBody getBytes:&_signatureType range:(NSRange){position,1}];
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
    NSData *hashedSubpacketsData = nil;
    if (hashedOctetCount > 0) {
        hashedSubpacketsData = [packetBody subdataWithRange:(NSRange){position,hashedOctetCount}];
        position = position + hashedOctetCount;

        NSUInteger positionSubpackets = 0;
        while (positionSubpackets < hashedSubpacketsData.length) {
            NSRange headerRange = (NSRange) {positionSubpackets, MIN(6,hashedSubpacketsData.length - positionSubpackets) }; // up to 5+1 octets
            UInt32 headerLength    = 0;
            UInt32 subpacketLength = 0;
            PGPSignatureSubpacketType subpacketType = [PGPSignatureSubpacket parseSubpacketHeader:[hashedSubpacketsData subdataWithRange:headerRange]
                                                                                     headerLength:&headerLength
                                                                                  subpacketLength:&subpacketLength];


            NSRange bodyRange = (NSRange){positionSubpackets + headerLength,subpacketLength};
            PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] initWithBody:[hashedSubpacketsData subdataWithRange:bodyRange]
                                                                                      type:subpacketType];
            [self.hashedSubpackets addObject:subpacket];

            positionSubpackets = bodyRange.location + bodyRange.length;
        }
    }

    // Two-octet scalar octet count for the following unhashed subpacket
    UInt16 unhashedOctetCount = 0;
    [packetBody getBytes:&unhashedOctetCount range:(NSRange){position, 2}];
    unhashedOctetCount = CFSwapInt16BigToHost(unhashedOctetCount);
    position = position + 2;

    // Unhashed subpacket data set (zero or more subpackets)
    NSData *unhashedSubpacketData = nil;
    if (unhashedOctetCount > 0) {
        unhashedSubpacketData = [packetBody subdataWithRange:(NSRange){position,unhashedOctetCount}];
        position = position + unhashedOctetCount;

        // Loop subpackets
        NSUInteger positionSubpackets = 0;
        while (positionSubpackets < unhashedSubpacketData.length) {
            UInt32 headerLength    = 0;
            UInt32 subpacketLength = 0;
            NSUInteger rangeLength = MIN(5,unhashedSubpacketData.length - positionSubpackets); // up to 5 octets
            PGPSignatureSubpacketType subpacketType = [PGPSignatureSubpacket parseSubpacketHeader:[unhashedSubpacketData subdataWithRange:(NSRange){positionSubpackets,rangeLength}]
                                                                                     headerLength:&headerLength
                                                                                  subpacketLength:&subpacketLength];

            PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] initWithBody:unhashedSubpacketData type:subpacketType];
            [self.unhashedSubpackets addObject:subpacket];

            positionSubpackets = positionSubpackets + headerLength + subpacketLength;
        }
    }

    // Two-octet field holding the left 16 bits of the signed hash value.
    UInt16 leftBits = 0;
    [packetBody getBytes:&leftBits range:(NSRange){position, 2}];
    leftBits = CFSwapInt16BigToHost(leftBits);
    position = position + 2;

    // 5.2.2. One or more multiprecision integers comprising the signature. This portion is algorithm specific
    switch (_publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA signature value m**d mod n.
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiN.length;
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            PGPMPI *mpiR = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiR.length;

            // MPI of DSA value s.
            PGPMPI *mpiS = [[PGPMPI alloc] initWithData:packetBody atPosition:position];
            position = position + mpiS.length;
        }
            break;
        default:
            break;
    }
}



@end
