#NSScanner for NSData and files

MKDataScanner is for raw data, what NSScanner is for NSString. Because files are scanned as streams, large files can be scanned with minimum memory usage. Dedicated data providers for files and NSData.

##Features

* NSScanner like interface.
* Scan stream of file data for low memory usage.

##Installation

CocoaPods

`pod 'MKDataScanner'`

##Usage
	
Scan file for sequence of bytes {0...8}

    UInt8 bytes[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	NSData *searchData = [NSData dataWithBytes:bytes length:sizeof(bytes)]

	MKDataScanner *scanner = [MKDataScanner scannerWithFileURL:@"/path/file.dat"];
	NSData *scannedData = nil;
	if ([scanner scanUpToData:searchData intoData:&scannedData]) {
		NSLog(@"scanned data: %@",scannedData);
	}

With convenience function scanUpToBytes
	
    UInt8 bytes[] = {0x03, 0x04, 0x05, 0x06};
    [dataScanner scanUpToBytes:&bytes length:sizeof(bytes) intoData:nil];

	
Scan for integer
	
	NSInteger integer;
	if ([scanner scanInteger:&integer]) {
		NSLog(@"integer: %@",integer);
	]

##Contact

Marcin Krzyżanowski [@krzyzanowskim](http://twitter.com/krzyzanowskim)