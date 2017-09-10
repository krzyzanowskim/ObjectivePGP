//
//  PGPKeyMaterial.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 25/08/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPMPI.h"

@interface PGPKeyMaterial: NSObject

@property (nonatomic) PGPMPI *n;
@property (nonatomic) PGPMPI *e;
@property (nonatomic) PGPMPI *d;
@property (nonatomic) PGPMPI *p;
@property (nonatomic) PGPMPI *q;
@property (nonatomic) PGPMPI *r;
@property (nonatomic) PGPMPI *g;
@property (nonatomic) PGPMPI *u;
@property (nonatomic) PGPMPI *x;
@property (nonatomic) PGPMPI *y;

@end
