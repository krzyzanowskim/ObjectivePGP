//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPVerification.h"
#import "PGPKeyID.h"

@implementation PGPVerification
-(NSString*)description{
    return [[super description] stringByAppendingFormat:@"code: %d, KeyID: %@, error: %@",self.verificationCode,self.keyID.longIdentifier,self.verificationError];
    
}
@end
