//
//  PGPSignaturePacket+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>

@interface PGPSignaturePacket ()

@property (nonatomic, copy, readwrite) NSArray<PGPSignatureSubpacket *> *hashedSubpackets;
@property (nonatomic, copy, readwrite) NSArray<PGPSignatureSubpacket *> *unhashedSubpackets;

@end
