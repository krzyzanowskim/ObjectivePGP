//
//  PGPPublicKeyEncryptedSessionKeyPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rencryptedMPIsPartDataights reserved.
//
//  5.1.  Public-Key Encrypted Session Key Packets (Tag 1)

#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPKeyID.h"
#import "PGPMPI.h"
#import "NSData+PGPUtils.h"
#import "PGPPKCSEme.h"
#import "PGPPublicKeyPacket.h"
#import "PGPMPI.h"

@interface PGPPublicKeyEncryptedSessionKeyPacket ()
@property (strong) NSData *encryptedMPI_M;
@end

@implementation PGPPublicKeyEncryptedSessionKeyPacket

- (instancetype)init
{
    if (self = [super init]) {
        self.version = 3;
        self.encrypted = NO;
        self.publicKeyAlgorithm = PGPPublicKeyAlgorithmRSA;
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPPublicKeyEncryptedSessionKeyPacketTag; // 1
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
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
    
    self.encryptedMPI_M = [packetBody subdataWithRange:(NSRange) {position, packetBody.length - position}];
    position = position + self.encryptedMPI_M.length;
    
    self.encrypted = YES;
    
    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    NSAssert(self.encryptedMPI_M, @"Missing encrypted mpi m");
    
    NSMutableData *bodyData = [NSMutableData data];
    
    [bodyData appendBytes:&_version length:1]; //1
    [bodyData appendData:[self.keyID exportKeyData]]; //8
    [bodyData appendBytes:&_publicKeyAlgorithm length:1]; //1
    [bodyData appendData:self.encryptedMPI_M]; // m
    
    NSMutableData *data = [NSMutableData data];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];

    return [data copy];
}

- (PGPPublicKeyEncryptedSessionKeyPacket *) decryptedPacket
{
    //TODO: decrypy from message decrypt
    // __ops_get_seckey_cb
    PGPPublicKeyEncryptedSessionKeyPacket *decryptedPacket = [self copy];
    decryptedPacket.encrypted = NO;
    
    // get pubkey by id
    
    // pkESKeyPacket.decrypt(privateKeyPacket);
    return decryptedPacket;
}

// encryption update self.encryptedMPIsPartData
- (void) encrypt:(PGPPublicKeyPacket *)publicKeyPacket sessionKeyData:(NSData *)sessionKeyData sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm error:(NSError * __autoreleasing *)error
{
    NSMutableData *mData = [NSMutableData data];

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
    
    [mData appendData:sessionKeyData];
    
    UInt16 checksum = [sessionKeyData pgpChecksum];
    checksum = CFSwapInt16HostToBig(checksum);
    [mData appendBytes:&checksum length:2];
    
    PGPMPI *modulusMPI = [publicKeyPacket publicMPI:@"N"];
    if (!modulusMPI)
        return;
    
    BIGNUM *nBigNumRef = modulusMPI.bignumRef;
    unsigned int k = (unsigned)BN_num_bytes(nBigNumRef);
    
    NSData *mEMEEncoded = [PGPPKCSEme encodeMessage:mData keyModulusLength:k error:error];
    PGPMPI *mpiEncoded = [[PGPMPI alloc] initWithData:[publicKeyPacket encryptData:mEMEEncoded withPublicKeyAlgorithm:self.publicKeyAlgorithm]];
    self.encryptedMPI_M = [mpiEncoded exportMPI];
}


#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone
{
    PGPPublicKeyEncryptedSessionKeyPacket *copy = [super copyWithZone:zone];
    copy->_version = self.version;
    copy->_keyID = self.keyID;
    copy->_publicKeyAlgorithm = self.publicKeyAlgorithm;
    copy->_encryptedMPI_M = self.encryptedMPI_M;
    return copy;
}

@end
