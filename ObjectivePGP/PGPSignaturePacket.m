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
#import "NSData+PGPUtils.h"

#import <openssl/rsa.h>
#import <openssl/dsa.h>
#import <openssl/bn.h>
#import <openssl/err.h>
#import <openssl/ssl.h>

static NSString * const PGPSignatureHeaderSubpacketLengthKey = @"PGPSignatureHeaderSubpacketLengthKey"; // UInt32
static NSString * const PGPSignatureHeaderLengthKey = @"PGPSignatureHeaderLengthKey"; // UInt32
static NSString * const PGPSignatureSubpacketTypeKey = @"PGPSignatureSubpacketTypeKey"; // PGPSignatureSubpacketType


@interface PGPSignaturePacket ()
@property (strong, readwrite, nonatomic) NSMutableArray *hashedSubpackets;
@property (strong, readwrite, nonatomic) NSMutableArray *unhashedSubpackets;
@end

@implementation PGPSignaturePacket

- (instancetype)init
{
    if (self = [super init]) {
        _version = 4;
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

    if (hashedSubpackets.count > 0) {
        NSMutableData *hsubpackets = [NSMutableData data];
        // Hashed subpacket data set (zero or more subpackets)
        for (PGPSignatureSubpacket *subpacket in hashedSubpackets) {
            NSError *error = nil;
            NSData *subpacketData = [subpacket exportSubpacket:&error];
            if (subpacketData && !error) {
                [hsubpackets appendData:subpacketData];
            }
        }

        // Two-octet scalar octet count for following hashed subpacket data.
        UInt16 hashedOctetCountBE = CFSwapInt16HostToBig(hsubpackets.length);
        [data appendBytes:&hashedOctetCountBE length:2];
        // Subpackets
        [data appendData:hsubpackets];
    } else {
        UInt16 zeroZero = 0;
        [data appendBytes:&zeroZero length:2];
    }
    
    return [data copy];
}

- (NSData *) buildFullSignatureData:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];

    NSData *signedPartData = [self buildSignedPart:self.hashedSubpackets];
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

    for (PGPMPI *mpi in self.signatureMPIs) {
        [data appendData:[mpi buildData]];
    }

    return [data copy];
}

#pragma mark - Sign

- (BOOL)canBeUsedToSign
{
    NSArray *subpackets = [self subpackets];
    for (PGPSignatureSubpacket *subpacket in subpackets) {
        if (subpacket.type == PGPSignatureSubpacketTypeKeyFlags) {
            NSArray *flags = subpacket.value;
            if ([flags containsObject:@(PGPSignatureFlagAllowSignData)]) {
                return YES;
            }
        }
    }
    return NO;
}

// 5.2.4.  Computing Signatures
// http://tools.ietf.org/html/rfc4880#section-5.2.4
// @see https://github.com/singpolyma/openpgp-spec/blob/master/key-signatures
- (NSData *) signData:(PGPKey *)secretKey data:(NSData *)inputData userIDPacket:(PGPUserIDPacket *)userIDPacket
{
    NSAssert(secretKey.type == PGPKeySecret,@"Need secret key");

    PGPSecretKeyPacket *primaryKeyPacket = (PGPSecretKeyPacket *)secretKey.primaryKeyPacket;

    NSMutableArray *signatureHashedSubpackets = [NSMutableArray array];
    // timestamp subpacket is required
    PGPSignatureSubpacket *creationTimeSubpacket = [[PGPSignatureSubpacket alloc] init];
    creationTimeSubpacket.type = PGPSignatureSubpacketTypeSignatureCreationTime;
    creationTimeSubpacket.value = [NSDate date];
    [signatureHashedSubpackets addObject:creationTimeSubpacket];


    // signed part data
    NSData *signedPartData = [self buildSignedPart:signatureHashedSubpackets];
    // calculate trailer
    NSData *trailerData = [self calculateTrailerFor:signedPartData];

    // build toSignData, toSign
    NSMutableData *toSignData = [NSMutableData data];
    switch (_type) {
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

            PGPSecretKeyPacket *primaryKeyPacket = (PGPSecretKeyPacket *)secretKey.primaryKeyPacket;
            if (self.version == 4) {
                NSData *keyData = [primaryKeyPacket exportPublicPacketOldStyle];
                [toSignData appendData:keyData];
            }

            NSAssert(userIDPacket.tag == PGPUserIDPacketTag, @"Invalid packet, expected user ID packet");
            if (userIDPacket.userID.length > 0) {
                // constant tag (1)
                UInt8 userIDConstant = 0xB4;
                [toSignData appendBytes:&userIDConstant length:1];

                // length (4)
                UInt32 userIDLength = (UInt32)userIDPacket.userID.length;
                userIDLength = CFSwapInt32HostToBig(userIDLength);
                [toSignData appendBytes:&userIDLength length:4];

                // data
                [toSignData appendData:[userIDPacket.userID dataUsingEncoding:NSUTF8StringEncoding]];
            }
            //TODO user attributes alternative
            //UInt8 userAttributeConstant = 0xD1;
            //[data appendBytes:&userAttributeConstant length:sizeof(userAttributeConstant)];
            
        }
            break;
            
        default:
            break;
    }

    //toHash = toSignData + signedPartData + trailerData;
    NSMutableData *toHashData = [NSMutableData dataWithData:toSignData];
    [toHashData appendData:signedPartData];
    [toHashData appendData:trailerData];

    NSData *hashData = nil;
    switch (self.hashAlgoritm) {
        case PGPHashMD5:
            hashData = [toHashData pgpMD5];
            break;
        case PGPHashSHA1:
            hashData = [toHashData pgpSHA1];
            break;
        case PGPHashSHA224:
            hashData = [toHashData pgpSHA224];
            break;
        case PGPHashSHA256:
            hashData = [toHashData pgpSHA256];
            break;
        case PGPHashSHA384:
            hashData = [toHashData pgpSHA384];
            break;
        case PGPHashSHA512:
            hashData = [toHashData pgpSHA512];
            break;
        case PGPHashRIPEMD160:
            hashData = [toHashData pgpRIPEMD160];
            break;

        default:
            break;
    }

    // Two-octet field holding the left 16 bits of the signed hash value.
    NSData *signedHashValue = [hashData subdataWithRange:(NSRange){0,2}];
    NSLog(@"signedHashValue %@",signedHashValue);

    //    == Computing Signatures ==
    // Packet body
    NSData *calculatedSignatureMPI = [self calcSign:secretKey data:toHashData];

    NSMutableData *signedPacketBody = [NSMutableData data];
    [signedPacketBody appendData:signedPartData];

    //TODO: refactor, this is NSDAta of unhashed subpacket - used in few places
    //-->
    // add unhashed PGPSignatureSubpacketTypeIssuer subpacket
    NSMutableArray *signatureUnhashedSubpackets = [NSMutableArray array];

    // issue subpacket is required
    PGPSignatureSubpacket *issuerSubpacket = [[PGPSignatureSubpacket alloc] init];
    issuerSubpacket.type = PGPSignatureSubpacketTypeIssuer;
    PGPKeyID *keyid = [[PGPKeyID alloc] initWithFingerprint:primaryKeyPacket.fingerprint];
    issuerSubpacket.value = keyid;
    [signatureUnhashedSubpackets addObject:issuerSubpacket];

    if (signatureUnhashedSubpackets.count > 0) {
        NSMutableData *unhashedSubpackets = [NSMutableData data];
        // Hashed subpacket data set (zero or more subpackets)
        for (PGPSignatureSubpacket *subpacket in signatureUnhashedSubpackets) {
            NSError *error = nil;
            NSData *subpacketData = [subpacket exportSubpacket:&error];
            if (subpacketData && !error) {
                [unhashedSubpackets appendData:subpacketData];
            }
        }
        // Two-octet scalar octet count for following hashed subpacket data.
        UInt16 unhashedOctetCountBE = CFSwapInt16HostToBig(unhashedSubpackets.length);
        [signedPacketBody appendBytes:&unhashedOctetCountBE length:2];
        // Subpackets
        [signedPacketBody appendData:unhashedSubpackets];
    } else {
        UInt16 zeroZero = 0;
        [signedPacketBody appendBytes:&zeroZero length:2];
    }
    //<--

    // Checksum
    [signedPacketBody appendData:signedHashValue];
    // MPI
    [signedPacketBody appendData:calculatedSignatureMPI];


    // Build final packet with header
    NSData *signedPacketHeader = [self buildHeaderData:signedPacketBody];
    NSMutableData *signedPacket = [NSMutableData dataWithData:signedPacketHeader];
    [signedPacket appendData:signedPacketBody];

    return [signedPacket copy];
}

- (NSData *) calcSign:(PGPKey *)secretKey data:(NSData *)toHashData
{
    // TODO: wielkie TODO: 5.2.2.
    // rsa_sign z prefixa itp, jak opisane dla wersji 3 ??? to nie ma sensu
    // a jednak tak
    // see Create a V4 public key signature over some cleartext.
    // __ops_start_sig
    // Opisa jest w V3, ale odnosi się również do V4

    NSAssert(secretKey.type == PGPKeySecret, @"Secret key expected");
    NSAssert(secretKey.primaryKeyPacket.tag == PGPSecretKeyPacketTag || secretKey.primaryKeyPacket.tag == PGPSecretSubkeyPacketTag, @"Private packet expected");

    if (secretKey.type == PGPKeyPublic) {
        return nil;
    }

    PGPSecretKeyPacket *secureKeyPacket = (PGPSecretKeyPacket *)secretKey.primaryKeyPacket;

    RSA *rsa = RSA_new();
    rsa->n = BN_dup([(PGPMPI*)secureKeyPacket[@"publicMPI.N"] bignumRef]);
	rsa->d = BN_dup([(PGPMPI*)secureKeyPacket[@"secretMPI.D"] bignumRef]);
	rsa->p = BN_dup([(PGPMPI*)secureKeyPacket[@"secretMPI.Q"] bignumRef]);	/* p and q are round the other way in openssl */
	rsa->q = BN_dup([(PGPMPI*)secureKeyPacket[@"secretMPI.P"] bignumRef]);
    rsa->e = BN_dup([(PGPMPI*)secureKeyPacket[@"publicMPI.E"] bignumRef]);

    int keysize = (BN_num_bits(rsa->n) + 7) / 8;

    // With RSA signatures, the hash value is encoded using PKCS#1 1.5
    // toHashData = [@"Plaintext\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *em = [PGPPKCSEmsa encode:self.hashAlgoritm m:toHashData emLen:keysize error:nil];

    /* If this isn't set, it's very likely that the programmer hasn't */
	/* decrypted the secret key. RSA_check_key segfaults in that case. */
	/* Use __ops_decrypt_seckey() to do that. */
	if (rsa->d == NULL) {
		return nil;
	}

    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (RSA_check_key(rsa) != 1) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(UInt8));
        ERR_error_string(err_code, errBuf);
        printf("%s\n",errBuf);
        free(errBuf);
		return nil;
	}


    UInt8 *outbuf = calloc(RSA_size(rsa), sizeof(UInt8));
    int n = RSA_private_encrypt(keysize, (UInt8 *)em.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (n < 0) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(UInt8));
        ERR_error_string(err_code, errBuf);
        printf("%s\n",errBuf);
        free(errBuf);
        return nil;
    }
    NSData *outData = [NSData dataWithBytes:outbuf length:n];

	//rsa->n = rsa->d = rsa->p = rsa->q = NULL;
    free(outbuf);
	RSA_free(rsa);

    ERR_free_strings();


    // build mpi
    PGPMPI *mpi = [[PGPMPI alloc] initWithData:outData];
    return [mpi buildData];
}

- (NSData *) calculateTrailerFor:(NSData *)signedPartData
{
    if (self.version < 4)
        return nil;

    NSMutableData *trailerData = [NSMutableData data];
    UInt8 version = 4;
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

    self.signedPartData = [packetBody subdataWithRange:(NSRange){startPosition, position}];
    NSLog(@"signatureData %@",self.signedPartData);

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
            PGPMPI *mpiN = [[PGPMPI alloc] initWithMPIData:packetBody atPosition:position];
            mpiN.identifier = @"N";
            position = position + mpiN.length;

            self.signatureMPIs = [NSArray arrayWithObject:mpiN];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            PGPMPI *mpiR = [[PGPMPI alloc] initWithMPIData:packetBody atPosition:position];
            mpiR.identifier = @"R";
            position = position + mpiR.length;

            // MPI of DSA value s.
            PGPMPI *mpiS = [[PGPMPI alloc] initWithMPIData:packetBody atPosition:position];
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
                                                                              type:subpacketType
                                                                             range:bodyRange];

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
