//
//  PGPSignature.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 30/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignature.h"

@implementation PGPSignature

- (instancetype)initWithPacket:(PGPSignaturePacket *)packet
{
    if (self = [super init]) {
        NSAssert([packet isKindOfClass:[PGPSignaturePacket class]], @"Invalid class");
        _packet = packet;
        _type = packet.signatureType;
        _creationDate = packet.creationDate;
        _issuerKeyID = [packet valueOfSubacketOfType:PGPSignatureSubpacketTypeIssuerKeyID found:nil];
    }
    return self;
}

@end
