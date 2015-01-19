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
#import "NSInputStream+PGP.h"

@implementation PGPMPI

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    PGPMPI *mpi = [[PGPMPI alloc] init];
    
    UInt16 bits = [inputStream readUInt16];
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

@end
