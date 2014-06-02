
#import <Foundation/Foundation.h>

@interface NSData (Stream)

+ (NSData*)dataWithStream:(FILE*)stream ;
- (void)writeToStream:(FILE*)stream ;
	
@end
