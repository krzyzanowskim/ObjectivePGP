//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPBigNum.h>
#import <ObjectivePGP/PGPMacros.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN


typedef NSString *PGPMPIdentifier NS_STRING_ENUM;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierN;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierE;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierP;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierG;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierQ;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierD;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierU;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierX;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierR;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierS;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierY;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierM;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierV;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierEC;
OBJC_EXTERN PGPMPIdentifier const PGPMPIdentifierEC_S;

@interface PGPMPI : NSObject <NSCopying>

@property (nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, readonly) PGPBigNum *bigNum;
/**
 *  Total bytes, header + body
 */
@property (nonatomic, readonly) NSUInteger packetLength;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithData:(NSData *)dataToMPI identifier:(NSString *)identifier NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithBigNum:(PGPBigNum *)bigNum identifier:(NSString *)identifier;
- (instancetype)initWithMPIData:(NSData *)mpiData identifier:(NSString *)identifier atPosition:(NSUInteger)position;
- (nullable NSData *)exportMPI;
- (nullable NSData *)bodyData;

@end

NS_ASSUME_NONNULL_END
