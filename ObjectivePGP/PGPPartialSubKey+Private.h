//
//  PGPPartialSubKey+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 30/09/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>

@interface PGPPartialSubKey ()

@property (nonatomic, nullable, readwrite) PGPSignaturePacket *bindingSignature;

@end
