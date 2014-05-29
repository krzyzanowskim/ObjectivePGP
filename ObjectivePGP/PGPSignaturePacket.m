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
#import "PGPPKCSEmsa.h"
#import "PGPLiteralPacket.h"
#import "PGPPublicKeyRSA.h"
#import "NSData+PGPUtils.h"

#import <openssl/rsa.h>
#import <openssl/dsa.h>
#import <openssl/bn.h>
#import <openssl/err.h>
#import <openssl/ssl.h>

@interface PGPSignaturePacket ()
@property (strong, readwrite, nonatomic) NSArray *hashedSubpackets;
@property (strong, readwrite, nonatomic) NSArray *unhashedSubpackets;

// A V4 signature hashes the packet body
// starting from its first field, the version number, through the end
// of the hashed subpacket data.  Thus, the fields hashed are the
// signature version, the signature type, the public-key algorithm, the
// hash algorithm, the hashed subpacket length, and the hashed
// subpacket body.
@property (strong) NSData *rawReadedSignedPartData;

@end

@implementation PGPSignaturePacket

- (instancetype)init
{
    if (self = [super init]) {
        _version = 4;
    }
    return self;
}

+ (PGPSignaturePacket *) signaturePacket:(PGPSignatureType)type hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm
{
    PGPSignaturePacket *signaturePacket = [[PGPSignaturePacket alloc] init];

    signaturePacket.hashAlgoritm = hashAlgorithm;
    return signaturePacket;
}

- (NSArray *)hashedSubpackets
{
    if (!_hashedSubpackets) {
        _hashedSubpackets = [NSArray array];
    }
    return _hashedSubpackets;
}

- (NSArray *)unhashedSubpackets
{
    if (!_unhashedSubpackets) {
        _unhashedSubpackets = [NSArray array];
    }
    return _unhashedSubpackets;

}

- (PGPPacketTag)tag
{
    return PGPSignaturePacketTag;
}


- (PGPKeyID *)issuerKeyID
{
    PGPSignatureSubpacket *subpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeIssuerKeyID] firstObject];
    return subpacket.value;
}

- (NSArray *)subpackets
{
    return [self.hashedSubpackets arrayByAddingObjectsFromArray:self.unhashedSubpackets];
}

- (NSArray *)subpacketsOfType:(PGPSignatureSubpacketType)type
{
    NSMutableArray *arr = [NSMutableArray array];
    for (PGPSignatureSubpacket *subPacket in self.subpackets) {
        if (subPacket.type == type) {
            [arr addObject:subPacket];
        }
    }
    return [arr copy];
}

- (NSDate *)expirationDate
{
    PGPSignatureSubpacket *creationDateSubpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeSignatureCreationTime] firstObject];
    PGPSignatureSubpacket *validityPeriodSubpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeSignatureExpirationTime] firstObject];

    NSDate *creationDate = creationDateSubpacket.value;
    NSNumber *validityPeriod = validityPeriodSubpacket.value;
    if (!validityPeriod || validityPeriod.unsignedIntegerValue == 0) {
        return nil;
    }

    NSDate *expirationDate = [creationDate dateByAddingTimeInterval:validityPeriod.unsignedIntegerValue];
    return expirationDate;
}

- (BOOL) isExpired
{
    // is no expiration date then signature never expires
    NSDate *expirationDate = [self expirationDate];
    if (!expirationDate) {
        return NO;
    }

    if ([expirationDate compare:[NSDate date]] == NSOrderedDescending) {
        return YES;
    }
    return NO;
}

- (NSDate *) creationDate
{
    PGPSignatureSubpacket *creationDateSubpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeSignatureCreationTime] lastObject];
    return creationDateSubpacket.value;
}

- (BOOL) isPrimaryUserID
{
    PGPSignatureSubpacket *primaryUserIDSubpacket =  [[self subpacketsOfType:PGPSignatureSubpacketTypePrimaryUserID] firstObject];
    return [(NSNumber *)primaryUserIDSubpacket boolValue];
}

#pragma mark - Build packet

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];

    NSData *bodyData = [self buildFullSignatureBodyData:error];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];

    return [data copy];
}

- (NSData *) buildSignedPart:(NSArray *)hashedSubpackets
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

    // hashed Subpackets
    [data appendData:[self buildSubpacketsCollectionData:hashedSubpackets]];

    return [data copy];
}

- (NSData *) buildFullSignatureBodyData:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];

    NSData *signedPartData = [self buildSignedPart:self.hashedSubpackets];
    [data appendData:signedPartData];

    // unhashed Subpackets
    [data appendData:[self buildSubpacketsCollectionData:self.unhashedSubpackets]];

    // signed hash value
    [data appendData:self.signedHashValueData];

    for (PGPMPI *mpi in self.signatureMPIs) {
        [data appendData:[mpi exportMPI]];
    }

    return [data copy];
}

#pragma mark - Verify

- (BOOL) verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey
{
    return [self verifyData:inputData withKey:publicKey signingKeyPacket:(PGPPublicKeyPacket *)publicKey.signingKeyPacket userID:nil];
}

- (BOOL) verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey userID:(NSString *)userID
{
    return [self verifyData:inputData withKey:publicKey signingKeyPacket:(PGPPublicKeyPacket *)publicKey.signingKeyPacket userID:userID];
}

// Opposite to sign, with readed data (not produced)
- (BOOL) verifyData:(NSData *)inputData withKey:(PGPKey *)publicKey signingKeyPacket:(PGPPublicKeyPacket *)signingKeyPacket userID:(NSString *)userID
{
    if (self.type == PGPSignatureBinaryDocument && inputData.length == 0) {
        return NO;
    }

    // build toSignData, toSign
    NSData *toSignData = [self toSignDataForType:self.type inputData:inputData key:publicKey keyPacket:signingKeyPacket userID:userID];

    // signedPartData
    NSData *signedPartData = [self buildSignedPart:self.hashedSubpackets];
    // calculate trailer
    NSData *trailerData = [self calculateTrailerFor:signedPartData];

    //toHash = toSignData + signedPartData + trailerData;
    NSMutableData *toHashData = [NSMutableData dataWithData:toSignData];
    [toHashData appendData:self.rawReadedSignedPartData];
    [toHashData appendData:trailerData];


    // Calculate hash value
    NSData *hashData = [toHashData pgpHashedWithAlgorithm:self.hashAlgoritm];

    // check signed hash value, should match
    if (![self.signedHashValueData isEqualToData:[hashData subdataWithRange:(NSRange){0,2}]]) {
        return NO;
    }

    switch (signingKeyPacket.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSASignOnly:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        {
            // convert mpi data to binary signature_bn_bin
            PGPMPI *signatureMPI = self.signatureMPIs[0];

            // encoded m value
            NSData *encryptedEmData = [signatureMPI bodyData];

            // decrypted encoded m value
            NSData *decryptedEmData = [PGPPublicKeyRSA publicDecrypt:encryptedEmData withPublicKeyPacket:signingKeyPacket];

            // calculate EM and compare with decrypted EM. PKCS-emsa Encoded M.
            NSError *error = nil; //TODO: handle
            NSData *emData = [PGPPKCSEmsa encode:self.hashAlgoritm message:toHashData encodedMessageLength:signingKeyPacket.keySize error:&error];
            if (![emData isEqualToData:decryptedEmData]) {
                return NO;
            }
        }
            break;
        default:
            break;
    }
    return YES;
}

#pragma mark - Sign

- (BOOL)canBeUsedToSign
{
    BOOL result = self.publicKeyAlgorithm == PGPPublicKeyAlgorithmDSA || self.publicKeyAlgorithm == PGPPublicKeyAlgorithmRSA || self.publicKeyAlgorithm == PGPPublicKeyAlgorithmRSASignOnly;

    if (result) {
        PGPSignatureSubpacket *subpacket = [[self subpacketsOfType:PGPSignatureSubpacketTypeKeyFlags] firstObject];
        NSArray *flags = subpacket.value;
        if ([flags containsObject:@(PGPSignatureFlagAllowSignData)]) {
            return YES;
        }
    }

    return NO;
}

// 5.2.4.  Computing Signatures
// http://tools.ietf.org/html/rfc4880#section-5.2.4
// @see https://github.com/singpolyma/openpgp-spec/blob/master/key-signatures
- (void) signData:(NSData *)inputData  secretKey:(PGPKey *)secretKey
{
    return [self signData:inputData secretKey:secretKey userID:nil];
}

- (void) signData:(NSData *)inputData secretKey:(PGPKey *)secretKey userID:(NSString *)userID
{
    NSAssert(secretKey.type == PGPKeySecret,@"Need secret key");
    NSAssert([secretKey.primaryKeyPacket isKindOfClass:[PGPSecretKeyPacket class]], @"Signing key packet not found");

    PGPSecretKeyPacket *signingKeyPacket = (PGPSecretKeyPacket *)secretKey.signingKeyPacket;
    NSAssert(signingKeyPacket, @"No signing signature found");
    if (!signingKeyPacket) {
        return;
    }

    // setup public key algorithm from secret key packet
    self.publicKeyAlgorithm = signingKeyPacket.publicKeyAlgorithm;

    // signed part data
    // timestamp subpacket is required
    PGPSignatureSubpacket *creationTimeSubpacket = [PGPSignatureSubpacket subpacketWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:[NSDate date]];
    self.hashedSubpackets = @[creationTimeSubpacket];
    NSData *signedPartData = [self buildSignedPart:self.hashedSubpackets];
    // calculate trailer
    NSData *trailerData = [self calculateTrailerFor:signedPartData];

    // build toSignData, toSign
    NSData *toSignData = [self toSignDataForType:self.type inputData:inputData key:secretKey keyPacket:signingKeyPacket userID:userID];
    //toHash = toSignData + signedPartData + trailerData;
    NSMutableData *toHashData = [NSMutableData dataWithData:toSignData];
    [toHashData appendData:signedPartData];
    [toHashData appendData:trailerData];

    // Calculate hash value
    NSData *hashData = [toHashData pgpHashedWithAlgorithm:self.hashAlgoritm];

    // == Computing Signatures ==
    // Encrypt hash data Packet signature MPIs
    // Encrypted m value (PKCS emsa encrypted)
    NSData *em = [PGPPKCSEmsa encode:self.hashAlgoritm message:toHashData encodedMessageLength:signingKeyPacket.keySize error:nil];
    NSData *encryptedEmData = nil;

    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            encryptedEmData = [PGPPublicKeyRSA privateEncrypt:em withSecretKeyPacket:signingKeyPacket];
        }
            break;

        default:
            [NSException raise:@"PGPNotSupported" format:@"Algorith not supported"];
            break;
    }

    NSAssert(encryptedEmData, @"Encryption failed");

    // store signature data as MPI
    self.signatureMPIs = @[[[PGPMPI alloc] initWithData:encryptedEmData]];

    // add unhashed PGPSignatureSubpacketTypeIssuer subpacket - REQUIRED
    PGPKeyID *keyid = [[PGPKeyID alloc] initWithFingerprint:signingKeyPacket.fingerprint];
    PGPSignatureSubpacket *issuerSubpacket = [PGPSignatureSubpacket subpacketWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:keyid];
    self.unhashedSubpackets = @[issuerSubpacket];

    // Checksum
    // Two-octet field holding the left 16 bits of the signed hash value.
    NSData *signedHashValue = [hashData subdataWithRange:(NSRange){0,2}];
    self.signedHashValueData = signedHashValue;
}

- (NSData *) toSignDataForType:(PGPSignatureType)type inputData:(NSData *)inputData key:(PGPKey *)key keyPacket:(PGPPublicKeyPacket *)keyPacket userID:(NSString *)userID
{
    NSMutableData *toSignData = [NSMutableData data];
    switch (type) {
        case PGPSignatureBinaryDocument:
        {
            // For binary document signatures (type 0x00), the document data is
            // hashed directly.
            [toSignData appendData:inputData];
        }
            break;
        case PGPSignatureCanonicalTextDocument:
        {
            // For text document signatures (type 0x01), the
            // document is canonicalized by converting line endings to <CR><LF>,
            // and the resulting data is hashed.
        }
            break;
        case PGPSignatureGenericCertificationUserIDandPublicKey: // 0x10
        case PGPSignaturePersonalCertificationUserIDandPublicKey:// 0x11
        case PGPSignatureCasualCertificationUserIDandPublicKey:  // 0x12
        case PGPSignaturePositiveCertificationUserIDandPublicKey:// 0x13
        case PGPSignatureCertificationRevocation:                // 0x28
        {
            // A certification signature (type 0x10 through 0x13)

            // When a signature is made over a key, the hash data starts with the
            // octet 0x99, followed by a two-octet length of the key, and then body
            // of the key packet. (Note that this is an old-style packet header for
            // a key packet with two-octet length.)

            if (self.version == 4) {
                NSData *keyData = [keyPacket exportPublicPacketOldStyle];
                [toSignData appendData:keyData];
            }

            NSAssert(key.users > 0, @"Key need at least one user");

            BOOL userIsValid = NO;
            for (PGPUser *user in key.users) {
                if ([user.userID isEqualToString:userID]) {
                    userIsValid = YES;
                }
            }

            if (!userIsValid) {
                return nil;
            }

            if (userID.length > 0) {
                // constant tag (1)
                UInt8 userIDConstant = 0xB4;
                [toSignData appendBytes:&userIDConstant length:1];

                // length (4)
                UInt32 userIDLength = (UInt32)userID.length;
                userIDLength = CFSwapInt32HostToBig(userIDLength);
                [toSignData appendBytes:&userIDLength length:4];

                // data
                [toSignData appendData:[userID dataUsingEncoding:NSUTF8StringEncoding]];
            }
            //TODO user attributes alternative
            //UInt8 userAttributeConstant = 0xD1;
            //[data appendBytes:&userAttributeConstant length:sizeof(userAttributeConstant)];
            
        }
            break;
            
        default:
            [toSignData appendData:inputData];
            break;
    }
    return [toSignData copy];
}

- (NSData *) calculateTrailerFor:(NSData *)signedPartData
{
    if (self.version < 4)
        return nil;

    NSMutableData *trailerData = [NSMutableData data];
    UInt8 version = 0x04;
    [trailerData appendBytes:&version length:1];

    UInt8 tag = 0xFF;
    [trailerData appendBytes:&tag length:1];

    UInt32 signatureLength = signedPartData.length; // + 6; // ??? (note that this number does not include these final six octets)
    signatureLength = CFSwapInt32HostToBig(signatureLength);
    [trailerData appendBytes:&signatureLength length:4];

    return [trailerData copy];
}

#pragma mark - Parse

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
    NSData *hashedSubpacketsData = nil;
    if (hashedOctetCount > 0) {
        hashedSubpacketsData = [packetBody subdataWithRange:(NSRange){position,hashedOctetCount}];
        position = position + hashedOctetCount;

        NSMutableArray *hashedSubpackets = [NSMutableArray arrayWithCapacity:hashedOctetCount];

        NSUInteger positionSubpacket = 0;
        while (positionSubpacket < hashedSubpacketsData.length) {
            PGPSignatureSubpacket *subpacket = [self getSubpacketStartingAtPosition:positionSubpacket fromData:hashedSubpacketsData];
            [hashedSubpackets addObject:subpacket];
            positionSubpacket = subpacket.bodyRange.location + subpacket.bodyRange.length;
        }

        self.hashedSubpackets = [hashedSubpackets copy];
    }

    // Raw, signed data
    self.rawReadedSignedPartData = [packetBody subdataWithRange:(NSRange){startPosition, position}];

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

        NSMutableArray *unhashedSubpackets = [NSMutableArray arrayWithCapacity:unhashedOctetCount];

        // Loop subpackets
        NSUInteger positionSubpacket = 0;
        while (positionSubpacket < unhashedSubpacketsData.length) {
            PGPSignatureSubpacket *subpacket = [self getSubpacketStartingAtPosition:positionSubpacket fromData:unhashedSubpacketsData];
            [unhashedSubpackets addObject:subpacket];
            positionSubpacket = subpacket.bodyRange.location + subpacket.bodyRange.length;
        }

        self.unhashedSubpackets = [unhashedSubpackets copy];
    }

    // Two-octet field holding the left 16 bits of the signed hash value.
    self.signedHashValueData = [packetBody subdataWithRange:(NSRange){position, 2}];
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
            PGPMPI *mpiN = [[PGPMPI alloc] initWithMPIData:packetBody atPosition:position];
            mpiN.identifier = @"N";
            position = position + mpiN.packetLength;

            self.signatureMPIs = [NSArray arrayWithObject:mpiN];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            PGPMPI *mpiR = [[PGPMPI alloc] initWithMPIData:packetBody atPosition:position];
            mpiR.identifier = @"R";
            position = position + mpiR.packetLength;

            // MPI of DSA value s.
            PGPMPI *mpiS = [[PGPMPI alloc] initWithMPIData:packetBody atPosition:position];
            mpiS.identifier = @"S";
            position = position + mpiS.packetLength;

            self.signatureMPIs = [NSArray arrayWithObjects:mpiR, mpiS, nil];
        }
            break;
        default:
            break;
    }

    return position;
}

#pragma mark - Private

// I don't like this part, really ugly
// This is because subpacket length is unknow and header need to be found first
// then subpacket can be parsed
- (PGPSignatureSubpacket *) getSubpacketStartingAtPosition:(NSUInteger)subpacketsPosition fromData:(NSData *)subpacketsData
{
    NSRange headerRange = (NSRange) {subpacketsPosition, MIN(6,subpacketsData.length - subpacketsPosition) }; // up to 5+1 octets
    NSData *guessHeaderData = [subpacketsData subdataWithRange:headerRange]; // this is "may be" header to be parsed
    PGPSignatureSubpacketHeader *subpacketHeader = [PGPSignatureSubpacket subpacketHeaderFromData:guessHeaderData];

    NSRange subPacketBodyRange = (NSRange){subpacketsPosition + subpacketHeader.headerLength,subpacketHeader.bodyLength};
    NSData *subPacketBody = [subpacketsData subdataWithRange:subPacketBodyRange];
    PGPSignatureSubpacket *subpacket = [[PGPSignatureSubpacket alloc] initWithHeader:subpacketHeader body:subPacketBody bodyRange:subPacketBodyRange];

    return subpacket;
}

- (NSData *) buildSubpacketsCollectionData:(NSArray *)subpacketsCollection
{
    NSMutableData *data = [NSMutableData data];
    if (subpacketsCollection.count > 0) {
        NSMutableData *subpackets = [NSMutableData data];
        // Hashed subpacket data set (zero or more subpackets)
        for (PGPSignatureSubpacket *subpacket in subpacketsCollection) {
            NSError *error = nil;
            NSData *subpacketData = [subpacket exportSubpacket:&error];
            if (subpacketData && !error) {
                [subpackets appendData:subpacketData];
            }
        }
        // Two-octet scalar octet count for following hashed subpacket data.
        UInt16 countBE = CFSwapInt16HostToBig(subpackets.length);
        [data appendBytes:&countBE length:2];
        // subackets data
        [data appendData:subpackets];
    } else {
        // 0x00 0x00
        UInt16 zeroZero = 0;
        [data appendBytes:&zeroZero length:2];
    }
    return [data copy];
}

@end
