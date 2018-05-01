//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

//  5.1.  Public-Key Encrypted Session Key Packets (Tag 1)

#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "NSData+PGPUtils.h"
#import "PGPCryptoUtils.h"
#import "PGPFingerprint.h"
#import "PGPKeyID.h"
#import "PGPMPI.h"
#import "PGPPKCSEme.h"
#import "PGPPublicKeyPacket.h"
#import "PGPRSA.h"
#import "PGPSecretKeyPacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPPublicKeyEncryptedSessionKeyPacket ()

// RSA
@property (nonatomic, copy) PGPMPI *encryptedMPI_M;

// Elgamal
@property (nonatomic, copy) PGPMPI *encryptedMPI_G;
@property (nonatomic, copy) PGPMPI *encryptedMPI_Y;

@end

@implementation PGPPublicKeyEncryptedSessionKeyPacket

- (instancetype)init {
    if (self = [super init]) {
        _version = 3;
        _encryptedWithPassword = NO;
        _publicKeyAlgorithm = PGPPublicKeyAlgorithmRSA;
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPPublicKeyEncryptedSessionKeyPacketTag; // 1
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // - A one-octet number giving the version number of the packet type. The currently defined value for packet version is 3.
    [packetBody getBytes:&_version range:(NSRange){position, 1}];
    NSAssert(self.version == 3, @"The currently defined value for packet version is 3");
    position = position + 1;

    // - An eight-octet number that gives the Key ID of the public key
    self.keyID = [[PGPKeyID alloc] initWithLongKey:[packetBody subdataWithRange:(NSRange){position, 8}]];
    NSAssert(self.keyID, @"Missing KeyID");
    position = position + 8;

    // - A one-octet number giving the public-key algorithm used.
    [packetBody getBytes:&_publicKeyAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // - A string of octets that is the encrypted session key.  This
    //   string takes up the remainder of the packet, and its contents are
    //   dependent on the public-key algorithm used.
    //   RSA 1 MPI
    //   Elgamal 2 MPI

    NSAssert(self.publicKeyAlgorithm == PGPPublicKeyAlgorithmRSA || self.publicKeyAlgorithm == PGPPublicKeyAlgorithmElgamal, @"Not supported.");

    let encryptedMPI_Data = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];

    if (self.publicKeyAlgorithm == PGPPublicKeyAlgorithmRSA) {
        // MPI of RSA encrypted value m**e mod n.
        self.encryptedMPI_M = [[PGPMPI alloc] initWithMPIData:encryptedMPI_Data identifier:PGPMPI_M atPosition:0];
        position = position + self.encryptedMPI_M.packetLength;
    }

    if (self.publicKeyAlgorithm == PGPPublicKeyAlgorithmElgamal) {
        // MPI of Elgamal (Diffie-Hellman) value g**k mod p.
        self.encryptedMPI_G = [[PGPMPI alloc] initWithMPIData:encryptedMPI_Data identifier:PGPMPI_G atPosition:0];
        position = position + self.encryptedMPI_G.packetLength;
        // MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
        self.encryptedMPI_Y = [[PGPMPI alloc] initWithMPIData:encryptedMPI_Data identifier:PGPMPI_Y atPosition:0 + self.encryptedMPI_G.packetLength];
        position = position + self.encryptedMPI_Y.packetLength;
    }

    self.encryptedWithPassword = YES;

    return position;
}

// encryption update self.encryptedMPIPartData
- (BOOL)encrypt:(PGPPublicKeyPacket *)publicKeyPacket sessionKeyData:(NSData *)sessionKeyData sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm error:(NSError * __autoreleasing _Nullable *)error {
    let mData = [NSMutableData data];

    //    The value "m" in the above formulas is derived from the session key
    //    as follows.  First, the session key is prefixed with a one-octet
    //    algorithm identifier that specifies the symmetric encryption
    //    algorithm used to encrypt the following Symmetrically Encrypted Data
    //    Packet.  Then a two-octet checksum is appended, which is equal to the
    //    sum of the preceding session key octets, not including the algorithm
    //    identifier, modulo 65536.  This value is then encoded as described in
    //    PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
    //    form the "m" value used in the formulas above.  See Section 13.1 of
    //    this document for notes on OpenPGP's use of PKCS#1.

    [mData appendBytes:&sessionKeyAlgorithm length:1];

    [mData appendData:sessionKeyData]; // keySize

    UInt16 checksum = [sessionKeyData pgp_Checksum];
    checksum = CFSwapInt16HostToBig(checksum);
    [mData appendBytes:&checksum length:2];

    let modulusMPI = [publicKeyPacket publicMPI:PGPMPI_N];
    if (!modulusMPI) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Cannot encrypt. Missing required MPI. Invalid key."}];
        }
        return NO;
    }

    unsigned int k = (unsigned int)modulusMPI.bigNum.bytesCount;

    let mEMEEncoded = [PGPPKCSEme encodeMessage:mData keyModulusLength:k error:error];
    let encryptedData = [publicKeyPacket encryptData:mEMEEncoded withPublicKeyAlgorithm:self.publicKeyAlgorithm];
    let mpiEncoded = [[PGPMPI alloc] initWithData:encryptedData identifier:PGPMPI_M];
    self.encryptedMPI_M = mpiEncoded;
    // TODO: Elgamal
    return YES;
}

- (nullable NSData *)decryptSessionKeyData:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm *)sessionKeyAlgorithm error:(NSError * __autoreleasing _Nullable *)error {
    NSAssert(!secretKeyPacket.isEncryptedWithPassphrase, @"Secret key can't be decrypted");

    let _Nullable secretKeyKeyID = [[PGPKeyID alloc] initWithFingerprint:secretKeyPacket.fingerprint];
    if (!secretKeyKeyID || !PGPEqualObjects(self.keyID, secretKeyKeyID)) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Invalid secret key used to decrypt session key, expected %@, got %@", self.keyID, secretKeyKeyID] }];
        }
        return nil;
    }

    // encrypted m value
    let encryptedM = [self.encryptedMPI_M bodyData];
    //TODO: Elgamal

    // decrypted m value
    let mEMEEncoded = [PGPCryptoUtils decrypt:encryptedM usingSecretKeyPacket:secretKeyPacket];
    let mData = [PGPPKCSEme decodeMessage:mEMEEncoded error:error];
    if (error && *error) {
        return nil;
    }

    NSUInteger position = 0;
    PGPSymmetricAlgorithm sessionKeyAlgorithmRead = PGPSymmetricPlaintext;
    [mData getBytes:&sessionKeyAlgorithmRead range:(NSRange){position, 1}];
    NSAssert(sessionKeyAlgorithmRead < PGPSymmetricMax, @"Invalid algorithm");
    if (sessionKeyAlgorithm) {
        *sessionKeyAlgorithm = sessionKeyAlgorithmRead;
    }
    position = position + 1;

    NSUInteger sessionKeySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:sessionKeyAlgorithmRead];
    if (sessionKeySize == NSNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Invalid session key size" }];
        }
        return nil;
    }
    let sessionKeyData = [mData subdataWithRange:(NSRange){position, sessionKeySize}];
    position = position + sessionKeySize;

    UInt16 checksum = 0;
    [mData getBytes:&checksum range:(NSRange){position, 2}];
    checksum = CFSwapInt16BigToHost(checksum);

    // validate checksum
    UInt16 calculatedChecksum = [sessionKeyData pgp_Checksum];
    if (calculatedChecksum != checksum) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Invalid session key, checksum mismatch" }];
        }
        return nil;
    }

    return sessionKeyData;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    //TODO: Elgamal
    if (!self.encryptedMPI_M) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Cannot export session key packet"}];
        }
        return nil;
    }

    let bodyData = [NSMutableData data];

    [bodyData appendBytes:&_version length:1]; // 1
    [bodyData appendData:[self.keyID export:nil]]; // 8
    [bodyData appendBytes:&_publicKeyAlgorithm length:1]; // 1

    // TODO: Elgamal
    let exportedMPI = [self.encryptedMPI_M exportMPI];
    if (!exportedMPI) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Cannot export session key packet"}];
        }
        return nil;
    }
    [bodyData appendData:exportedMPI]; // m

    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return bodyData;
    }];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToSessionKeyPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToSessionKeyPacket:(PGPPublicKeyEncryptedSessionKeyPacket *)packet {
    return self.version == packet.version &&
           self.publicKeyAlgorithm == packet.publicKeyAlgorithm &&
           self.encryptedWithPassword == packet.encryptedWithPassword &&
           PGPEqualObjects(self.keyID, packet.keyID) &&
           PGPEqualObjects(self.encryptedMPI_M, packet.encryptedMPI_M) &&
           PGPEqualObjects(self.encryptedMPI_G, packet.encryptedMPI_G) &&
           PGPEqualObjects(self.encryptedMPI_Y, packet.encryptedMPI_Y);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.version;
    result = prime * result + self.publicKeyAlgorithm;
    result = prime * result + self.keyID.hash;
    result = prime * result + self.encryptedWithPassword;
    result = prime * result + self.encryptedMPI_M.hash;
    result = prime * result + self.encryptedMPI_G.hash;
    result = prime * result + self.encryptedMPI_Y.hash;
    return result;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([super copyWithZone:zone], PGPPublicKeyEncryptedSessionKeyPacket);
    PGPAssertClass(duplicate, PGPPublicKeyEncryptedSessionKeyPacket);
    duplicate.version = self.version;
    duplicate.publicKeyAlgorithm = self.publicKeyAlgorithm;
    duplicate.encryptedWithPassword = self.encryptedWithPassword;
    duplicate.keyID = self.keyID;
    duplicate.encryptedMPI_M = self.encryptedMPI_M;
    duplicate.encryptedMPI_G = self.encryptedMPI_G;
    duplicate.encryptedMPI_Y = self.encryptedMPI_Y;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
