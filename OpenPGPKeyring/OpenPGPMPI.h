//
//  OpenPGPMPI.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OpenPGPMPI : NSObject

/**
 *  Total bytes, header + body
 */
@property (assign) NSUInteger length;

- (instancetype) initWithData:(NSData *)data atPosition:(NSUInteger)position;

@end
