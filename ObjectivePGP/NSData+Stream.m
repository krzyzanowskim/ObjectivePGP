#import "NSData+Stream.h"

@implementation NSData (Stream)

#define STDIN_CHUNK_SIZE 1024

+ (NSData*)dataWithStream:(FILE*)stream
{
    @autoreleasepool {
        NSMutableData* data = [[NSMutableData alloc] init] ;
        unsigned char *buf = NULL ;
        NSInteger inBytes;
        do {
            buf = (unsigned char*)malloc(STDIN_CHUNK_SIZE);
            inBytes = fread(buf, 1, STDIN_CHUNK_SIZE, stream);
            [data appendBytes:buf
                       length:inBytes] ;
            free(buf) ;
        } while (inBytes > 0) ;
        NSData* output = [NSData dataWithData:data] ;
        return output ;
    }
}

- (void)writeToStream:(FILE*)stream {
	NSInteger size = [self length] ;
	if (size > 0) {
		void* buffer = malloc(size) ;
		[self getBytes:buffer] ;
		fwrite(buffer, 1, size, stream) ;	
		free(buffer) ;
	}
}

@end
