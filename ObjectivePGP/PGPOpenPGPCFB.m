//
//  PGPOpenPGPCFB.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPOpenPGPCFB.h"
#import "PGPTypes.h"
#import "PGPCryptoUtils.h"
#import "NSData+PGPUtils.h"

@implementation PGPOpenPGPCFB

+ (NSData *) encryptData:(NSData *)toEncrypt
              prefixData:(NSData *)prefixData // random data with length block size + 2
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData
{
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];

    NSAssert(prefixData.length != blockSize + 2, @"Invalid prefix data");
    
    //  1.  The feedback register (FR) is set to the IV, which is all zeros.
    NSMutableData *FR = [NSMutableData dataWithLength:blockSize];
    //  2.  FR is encrypted to produce FRE (FR Encrypted).  This is the encryption of an all-zero value.
    NSData *FRE = [FR encryptBlockWithSymmetricAlgorithm:symmetricAlgorithm sessionKeyData:sessionKeyData];
    //  3.  FRE is xored with the first BS octets of random data prefixed to
    //  the plaintext to produce C[1] through C[BS], the first BS octets
    //  of ciphertext.
    const UInt8 *fre_bytes = FRE.bytes;
    const UInt8 *prefix_bytes = prefixData.bytes;
    UInt8 xored[blockSize];
    for (int i = 0; i < blockSize; i++) {
        xored[i] = fre_bytes[i] ^ prefix_bytes[i];
    }
    NSData *C = [NSData dataWithBytes:xored length:sizeof(xored)];
    // 4.  FR is loaded with C[1] through C[BS].
    [FR setData:[C subdataWithRange:(NSRange){0,blockSize}]];
    // 5.  FR is encrypted to produce FRE, the encryption of the first BS
    //     octets of ciphertext.
    FRE = [FR encryptBlockWithSymmetricAlgorithm:symmetricAlgorithm sessionKeyData:sessionKeyData];
    // 6.  The left two octets of FRE get xored with the next two octets of
    //     data that were prefixed to the plaintext.  This produces C[BS+1]
    //     and C[BS+2], the next two octets of ciphertext.
    
    __weak typeof(self) weakSelt = self;
    
    return nil;
}

@end
