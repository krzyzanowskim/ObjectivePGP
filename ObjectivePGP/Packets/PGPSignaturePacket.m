//
//  PGPSignaturePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//    5.2.  Signature Packet (Tag 2)
//    A Signature packet describes a binding between some public key and
//    some data.  The most common signatures are a signature of a file or a
//    block of text, and a signature that is a certification of a User ID.

#import "PGPSignaturePacket.h"
#import "NSInputStream+PGP.h"
#import "NSOutputStream+PGP.h"
#import "PGPCommon.h"
#import "PGPMPI.h"
#import "PGPSignatureSubpacket.h"
#import "NSMutableData+PGP.h"

@interface PGPSignaturePacket ()
@property (copy, nonatomic) NSArray *hashedSubpackets;
@property (copy, nonatomic) NSArray *unhashedSubpackets;
@end

@implementation PGPSignaturePacket

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    PGPSignaturePacket *packet = [[PGPSignaturePacket alloc] init];
    
    // One-octet version number
    packet.version = [inputStream readUInt8];
    
    NSAssert(packet.version == 3 || packet.version == 4, @"Invalid version of signature packet");
    if (packet.version < 3 && packet.version > 4) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid version of signature packet"}];
        }
        return nil;
    }
    
    switch (packet.version) {
        case 0x03:
            [packet readV3FromStream:inputStream error:error];
            break;
        case 0x04:
            [packet readV4FromStream:inputStream error:error];
            break;
        default:
            NSAssert(false, @"Should never happened.");
            return nil;
    }
    
    return packet;
}

- (BOOL) readV3FromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    // One-octet length of following hashed material.  MUST be 5.
    UInt8 hashedLength = [inputStream readUInt8];
    NSAssert(hashedLength == 5, @"MUST be 5");
    if (hashedLength != 5) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid version of signature packet. Expected length equal 5."}];
        }
        return NO;
    }
    
    // - One-octet signature type.
    self.signatureType = [inputStream readUInt8];
    
    // - Four-octet creation time
    UInt32 timestamp = [inputStream readUInt32BE];
    self.creationDate = [NSDate dateWithTimeIntervalSince1970:timestamp];
    
    //Eight-octet Key ID of signer
    NSData *issuerKeyIDData = [inputStream readDataLength:8];
    self.issuerKeyID = [[PGPKeyID alloc] initWithBytes:issuerKeyIDData.bytes length:issuerKeyIDData.length];
    
    // One-octet public-key algorithm.
    self.publicKeyAlgorithm = [inputStream readUInt8];
    
    // One-octet hash algorithm.
    self.hashAlgoritm = [inputStream readUInt8];
    
    // Two-octet field holding the left 16 bits of the signed hash value.
    UInt16 signedHashValue = [inputStream readUInt16BE];
    self.hashValue = signedHashValue;
    
    // 5.2.2. One or more multiprecision integers comprising the signature. This portion is algorithm specific Signature
    NSMutableSet *mpis = [NSMutableSet set];
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA signature value m**d mod n.
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [PGPMPI readFromStream:inputStream error:error];
            mpiN.identifier = @"N";
            [mpis addObject:mpiN];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            PGPMPI *mpiR = [PGPMPI readFromStream:inputStream error:error];
            mpiR.identifier = @"R";
            [mpis addObject:mpiR];
            
            // MPI of DSA value s.
            PGPMPI *mpiS = [PGPMPI readFromStream:inputStream error:error];
            mpiS.identifier = @"S";
            [mpis addObject:mpiS];
        }
            break;
        default:
            NSAssert(false, @"Invalid public key algorithm. RSA or DSA expected.");
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid public key algorithm. RSA or DSA expected."}];
            }
            return NO;
    }
    
    self.MPIs = [mpis copy];
    
    //TODO: verify hash with hashed packets
    NSAssert(false, @"to be done... need V3 key for testing");
    return YES;
}

- (BOOL) readV4FromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    NSMutableData *toHashData = [NSMutableData dataWithBytes:(UInt8[]){0x04} length:1]; // data to hash
    
    //-->HASHED
    // One-octet signature type.
    self.signatureType = [inputStream readUInt8BytesAppendTo:toHashData];
    
    // One-octet public-key algorithm.
    self.publicKeyAlgorithm = [inputStream readUInt8BytesAppendTo:toHashData];
    
    // One-octet hash algorithm.
    self.hashAlgoritm = [inputStream readUInt8BytesAppendTo:toHashData];

    // Two-octet scalar octet count for following hashed subpacket data.
    UInt16 hashedSubpacketsBytes = [inputStream readUInt16BEBytesAppendTo:toHashData];
    UInt16 consumedBytes = 0;
    if (hashedSubpacketsBytes) {
        while (consumedBytes < hashedSubpacketsBytes) {
            NSData *rawData;
            PGPSignatureSubpacket *subpacket = [PGPSignatureSubpacket readFromStream:inputStream data:&rawData error:error];
            if (*error) {
                return NO;
            }
            consumedBytes += subpacket.totalLength;
            self.hashedSubpackets = [self.hashedSubpackets arrayByAddingObject:subpacket];
            [toHashData appendData:rawData];
        }
    }
    //-->HASHED
    
    // Two-octet scalar octet count for following unhashed subpacket data.
    UInt16 unhashedSubpacketsBytes = [inputStream readUInt16BE];
    consumedBytes = 0;
    if (unhashedSubpacketsBytes) {
        while (consumedBytes < unhashedSubpacketsBytes) {
            PGPSignatureSubpacket *subpacket = [PGPSignatureSubpacket readFromStream:inputStream data:nil error:error];
            if (*error) {
                return NO;
            }
            consumedBytes += subpacket.totalLength;
            self.unhashedSubpackets = [self.unhashedSubpackets arrayByAddingObject:subpacket];
        }
    }
    
    // Two-octet field holding the left 16 bits of the signed hash value.
    UInt16 signedHashValue = [inputStream readUInt16BE];
    self.hashValue = signedHashValue;

    // One or more multiprecision integers comprising the signature.
    NSMutableSet *mpis = [NSMutableSet set];
    switch (self.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // multiprecision integer (MPI) of RSA signature value m**d mod n.
            // MPI of RSA public modulus n;
            PGPMPI *mpiN = [PGPMPI readFromStream:inputStream error:error];
            if (*error) {
                return NO;
            }
            mpiN.identifier = @"N";
            [mpis addObject:mpiN];
        }
            break;
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDSA:
        {
            // MPI of DSA value r.
            PGPMPI *mpiR = [PGPMPI readFromStream:inputStream error:error];
            if (*error) {
                return NO;
            }
            mpiR.identifier = @"R";
            [mpis addObject:mpiR];
            
            // MPI of DSA value s.
            PGPMPI *mpiS = [PGPMPI readFromStream:inputStream error:error];
            if (*error) {
                return NO;
            }
            mpiS.identifier = @"S";
            [mpis addObject:mpiS];
            
        }
            break;
        default:
            NSAssert(false, @"Invalid public key algorithm. RSA or DSA expected.");
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid public key algorithm. RSA or DSA expected."}];
            }
            return NO;
    }
    
    self.MPIs = [mpis copy];
    self.creationDate = [self valueOfSubacketOfType:PGPSignatureSubpacketTypeSignatureCreationTime found:nil];
    
    //TODO: verify hash with hashed packets
    // Validate hash by computing hash against toHashData and compare with signedHashValue
    return YES;
}

- (id) valueOfSubacketOfType:(PGPSignatureSubpacketType)type found:(BOOL *)isFound
{
    for (PGPSignatureSubpacket *subpacket in [self.hashedSubpackets arrayByAddingObjectsFromArray:self.unhashedSubpackets]) {
        if (subpacket.type == type) {
            if (isFound) {
                *isFound = YES;
            }
            return subpacket.value;
        }
    }
    if (isFound) {
        *isFound = NO;
    }
    return nil;
}

#pragma write - Output

- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(outputStream);
    if (self.version == 0x03 && error) {
        *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Can't export signature with version 0x03"}];
        return NO;
    }
    
    NSMutableData *outputData = [NSMutableData data];
    
    [outputData appendUInt8:self.version];
    switch (self.version) {
        case 0x04:
        {
            [outputData appendUInt8:self.signatureType];
            [outputData appendUInt8:self.publicKeyAlgorithm];
            [outputData appendUInt8:self.hashAlgoritm];
            
            // hashed subpackets
            if (self.hashedSubpackets.count > 0) {
                NSMutableData *subpacketsData = [NSMutableData dataWithCapacity:256];
                for (PGPSignatureSubpacket *subpacket in self.hashedSubpackets) {
                    [subpacket appendToData:subpacketsData error:error];
                }
                [outputData appendUInt16BE:subpacketsData.length];
                [outputData appendData:subpacketsData];
            }
            
            // unhashed subpackets
            if (self.unhashedSubpackets.count > 0) {
                NSMutableData *subpacketsData = [NSMutableData dataWithCapacity:256];
                for (PGPSignatureSubpacket *subpacket in self.unhashedSubpackets) {
                    [subpacket appendToData:subpacketsData error:error];
                }
                [outputData appendUInt16BE:subpacketsData.length];
                [outputData appendData:subpacketsData];
            } else {
                [outputData appendUInt16BE:0x0000];
            }

            NSAssert(self.hashValue != 0, @"Calculate hash");
            [outputData appendUInt16BE:self.hashValue]; //Two-octet field holding the left 16 bits of the signed hash value.
            

            // MPI
            NSOutputStream *mpiStream = [NSOutputStream outputStreamToMemory];
            [mpiStream open];
            for (PGPMPI *mpi in self.MPIs) {
                if (![mpi writeToStream:mpiStream error:error]) {
                    return NO;
                }
            }
            [mpiStream close];
            [outputData appendData:[mpiStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey]];
        }
        break;
        case 0x03:
        {
            //TODO: Export V3 Signature
            NSAssert(false, @"Can't export version 0x03");
            return NO;
        }
        default:
        break;
    }
    
    return [outputStream writeData:outputData];
}

#pragma mark - Properties

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

@end
