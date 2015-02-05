//
//  PGPPublicKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

// 9.1.  Public-Key Algorithms
typedef NS_ENUM(UInt8, PGPPublicKeyAlgorithm) {
    PGPPublicKeyAlgorithmRSA                  = 1,
    PGPPublicKeyAlgorithmRSAEncryptOnly       = 2,
    PGPPublicKeyAlgorithmRSASignOnly          = 3,
    PGPPublicKeyAlgorithmElgamal              = 16,// Elgamal (Encrypt-Only)
    PGPPublicKeyAlgorithmDSA                  = 17,
    PGPPublicKeyAlgorithmElliptic             = 18,
    PGPPublicKeyAlgorithmECDSA                = 19,
    PGPPublicKeyAlgorithmElgamalEncryptorSign = 20,// Deprecated ?
    PGPPublicKeyAlgorithmDiffieHellman        = 21,
    PGPPublicKeyAlgorithmPrivate1             = 100,
    PGPPublicKeyAlgorithmPrivate2             = 101,
    PGPPublicKeyAlgorithmPrivate3             = 102,
    PGPPublicKeyAlgorithmPrivate4             = 103,
    PGPPublicKeyAlgorithmPrivate5             = 104,
    PGPPublicKeyAlgorithmPrivate6             = 105,
    PGPPublicKeyAlgorithmPrivate7             = 106,
    PGPPublicKeyAlgorithmPrivate8             = 107,
    PGPPublicKeyAlgorithmPrivate9             = 108,
    PGPPublicKeyAlgorithmPrivate10            = 109,
    PGPPublicKeyAlgorithmPrivate11            = 110,
};

@interface PGPPublicKeyPacket : NSObject
@property (assign)  NSUInteger version; // 0x03 or 0x04
@property (copy) NSDate *createDate;
@property (assign) PGPPublicKeyAlgorithm keyAlgorithm;
@property (assign) NSUInteger validityPeriod; // v3 only
@property (strong) NSSet *MPIs; // key algorithm specific MPIs

+ (instancetype) readFromStream:(NSInputStream *)inputStream maxLength:(NSUInteger)maxLength error:(NSError * __autoreleasing *)error;
- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error;

@end
