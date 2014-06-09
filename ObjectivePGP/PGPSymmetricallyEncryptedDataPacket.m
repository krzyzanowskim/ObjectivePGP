//
//  PGPSymmetricallyEncryptedDataPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPKey.h"
#import "PGPPublicKeyRSA.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"

@implementation PGPSymmetricallyEncryptedDataPacket

- (PGPPacketTag)tag
{
    return PGPSymmetricallyEncryptedDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // The content of an encrypted data packet is more OpenPGP packets
    // once decrypted, so recursively handle them

    // - Encrypted data, the output of the selected symmetric-key cipher
    // operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
    self.encryptedData = packetBody;
    
    position = position + packetBody.length;
    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    if (!self.encryptedData)
    {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"No encrypted data? try encrypt first"}];
        }
        return nil;
    }
    
    NSMutableData *data = [NSMutableData data];
    NSData *bodyData = self.encryptedData;
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];
    return [data copy];
}


// returns decrypted data
//- (NSData *) decrypt:(PGPSecretKeyPacket *)secretKeyPacket
//{
//    return [PGPPublicKeyRSA privateDecrypt:self.encryptedData withSecretKeyPacket:secretKeyPacket];
//}

- (void) encrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData
{
    switch (publicKeyPacket.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // ivData is block size long with zeroes here
            NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];
            UInt8 *zeroes = calloc(blockSize, sizeof(UInt8));
            NSMutableData *ivData = [NSMutableData dataWithBytes:zeroes length:blockSize];
            free(zeroes);
            
            // preamble
//            NSMutableData *preambleData = [NSMutableData data];
//            for (int i = 0; i < blockSize; i++) {
//                UInt8 randomByte = arc4random_uniform(126) + 1;
//                [preambleData appendBytes:&randomByte length:sizeof(randomByte)];
//            }
//            [preambleData appendData:[preambleData subdataWithRange:(NSRange){preambleData.length - 1,2}]];
            
            NSMutableData *toEncryptWithPreamble = [NSMutableData data];
//            [toEncryptWithPreamble appendData:preambleData];
            [toEncryptWithPreamble appendData:toEncrypt];
            
            NSData *encryptedData = [PGPCryptoCFB encryptData:toEncrypt sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData];
            self.encryptedData = encryptedData;
        }
            break;
        default:
            //TODO: add algorithms
            [NSException raise:@"PGPNotSupported" format:@"Algorith not supported"];
            break;
    }
}

@end
