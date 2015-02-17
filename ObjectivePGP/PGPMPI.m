//
//  PGPMPI.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//  3.2.  Multiprecision Integers
//  Multiprecision integers (also called MPIs) are unsigned integers used
//  to hold large integers such as the ones used in cryptographic
//  calculations.

#import "PGPMPI.h"
#import "PGPCommon.h"
#import "PGPFunctions.h"
#import "NSInputStream+PGP.h"
#import "NSOutputStream+PGP.h"
#import "NSMutableData+PGP.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation PGPMPI

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(inputStream);
    
    PGPMPI *mpi = [[PGPMPI alloc] init];
    
    UInt16 bits = [inputStream readUInt16BE];
    NSUInteger bytesCount = (bits + 7) / 8;
    
    UInt8 *mpiBuffer = calloc(1, bytesCount);
    NSInteger readResult = [inputStream read:mpiBuffer maxLength:bytesCount];
    if (readResult < 0 || readResult != bytesCount) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Error while reading MPI data."}];
        }
        return nil;
    }
    
    mpi.data = [NSData dataWithBytes:mpiBuffer length:bytesCount];
    
    // forget buffer
    memset(mpiBuffer, arc4random(), bytesCount);
    free(mpiBuffer);
    
    return mpi;
}

- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(outputStream);
    
    if (!outputStream.hasSpaceAvailable) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"No space on stream"}];
        }
        return NO;
    }
    
    NSData *mpiData = [self buildData:error];
    if (!mpiData || *error) {
        return NO;
    }
    
    return [outputStream writeData:mpiData];
}

- (NSData *) buildData:(NSError * __autoreleasing *)error
{
    NSData *data = [PGPMPI buildMPIForData:self.data error:error];
    if (!data || *error) {
        return nil;
    }
    return data;
}

#pragma mark - Private

+ (NSData *) buildMPIForData:(NSData *)data error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(data);
    
    if (!data) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Missing MPI data"}];
        }
        return nil;
    }
    
    NSMutableData *outData = [NSMutableData data];

    // length in bits
    UInt16 bits = pgpNumBits((Byte *)[data bytes], data.length);
    UInt16 bitsBE = CFSwapInt16HostToBig(bits);
    [outData appendBytes:&bitsBE length:2];
    
    // mpi
    [outData appendData:data];
    
//    // length
//    UInt16 bits = BN_num_bits(self.bignumRef);
//    UInt16 bitsBE = CFSwapInt16HostToBig(bits);
//    [outData appendBytes:&bitsBE length:2];
//    
//    // mpi
//    UInt8 *buf = calloc(BN_num_bytes(self.bignumRef), sizeof(UInt8));
//    UInt16 bytes = (bits + 7) / 8;
//    BN_bn2bin(self.bignumRef, buf);
//    [outData appendBytes:buf length:bytes];
//    free(buf);
    
    return [outData copy];
}

@end
