//
//  PGPSignatureSubpacket+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPSignatureSubpacket ()

@property (nonatomic, readwrite, copy) id<NSObject, NSCopying> value;

@end
