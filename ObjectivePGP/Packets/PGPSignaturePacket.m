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
#import "PGPCommon.h"

@implementation PGPSignaturePacket
+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    PGPSignaturePacket *packet = [[PGPSignaturePacket alloc] init];
    
    // One-octet version number
    UInt8 version = [inputStream readUInt8];
    NSAssert(version == 3 || version == 4, @"Invalid version of signature packet");
    if (version < 3 && version > 4) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid version of signature packet"}];
        }
        return nil;
    }
    
    if (version == 0x03) {
        // One-octet length of following hashed material. MUST be 5.
    }
    
    if (version == 0x04) {
        UInt8 hashedLength = [inputStream readUInt8];
        NSAssert(hashedLength == 5, @"MUST be 5");
        if (hashedLength != 5) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid version of signature packet"}];
            }
            return nil;
        }
        // One-octet signature type.
        packet.signatureType = [inputStream readUInt8];
        
        // Four-octet creation time
        UInt32 timestamp = [inputStream readUInt32];
        packet.creationData = [NSDate dateWithTimeIntervalSince1970:timestamp];
        
        // Eight-octet Key ID of signer
        UInt8 *keyIDBuffer = calloc(1, 8);
        NSInteger readResult = [inputStream read:keyIDBuffer maxLength:8];
        if (readResult > 0) {
            packet.keyID = [NSData dataWithBytes:keyIDBuffer length:readResult];
        }
        free(keyIDBuffer);
        
        // One-octet public-key algorithm.
        packet.publicKeyAlgorithm = [inputStream readUInt8];
        
        // One-octet hash algorithm.
        packet.hashAlgoritm = [inputStream readUInt8];
        
        // Two-octet field holding the left 16 bits of the signed hash value.
        //TODO: check if BE-LE is fine after readUInt16
    }
    
    return nil;
}
@end
