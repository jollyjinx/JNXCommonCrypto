//
//  JNXSHA1Tests.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 3/15/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

#import "JNXSHA1Tests.h"
#import "JNXCommonCrypto.h"
@implementation JNXSHA1Tests


- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

- (void)testExample1
{
	const char	*quickbrowntxt	 		= "The quick brown fox jumps over the lazy dog.";
	NSData 		*quickbrownTXTData		= [NSData dataWithBytes:quickbrowntxt length:strlen(quickbrowntxt)];

	uint8_t  	quickbrownsha1[] 		= { 0x40,0x8d,0x94,0x38,0x42,0x16,0xf8,0x90,0xff,0x7a,0x0c,0x35,0x28,0xe8,0xbe,0xd1,0xe0,0xb0,0x16,0x21 };
	NSData 		*quickbrownSHA1Data		= [NSData dataWithBytes:quickbrownsha1 length:sizeof(quickbrownsha1)];
	NSString	*quickbrownSHA1String	= @"408D94384216F890FF7A0C3528E8BED1E0B01621";
	
	if(![quickbrownTXTData sha1DataCompatible]) 																XCTFail(@"Sha1 of data does return nil");
	if(![[quickbrownTXTData sha1DataCompatible] isEqualToData:[quickbrownTXTData sha1DataCompatible]]) 			XCTFail(@"Sha1 of data stays not the same");
	if(![[quickbrownTXTData sha1DataCompatible] isEqualToData:quickbrownSHA1Data])								XCTFail(@"Wrong sha1 data for quick brown fox:%@",[quickbrownTXTData sha1DataCompatible]);
	if([[quickbrownTXTData sha1StringCompatible] isEqualToString:quickbrownSHA1String])							XCTFail(@"Wrong sha1 string for quick brown fox:%@",[quickbrownTXTData sha1StringCompatible]);
	if(![[quickbrownTXTData sha1StringCompatible] isEqualToString:[quickbrownSHA1String lowercaseString]])		XCTFail(@"Wrong sha1 string for quick brown fox:%@",[quickbrownTXTData sha1StringCompatible]);
}
- (void)testExample2
{
	const char	*quickbrowntxt	 = "The quick brown fox jumps over the lazy dog";
	uint8_t  	quickbrownsha1[] = { 0x2f,0xd4,0xe1,0xc6,0x7a,0x2d,0x28,0xfc,0xed,0x84,0x9e,0xe1,0xbb,0x76,0xe7,0x39,0x1b,0x93,0xeb,0x12 };

	NSData *data = [NSData dataWithBytes:quickbrowntxt length:strlen(quickbrowntxt)];

	NSData *resultSHA1 = [data sha1DataCompatible];

	if(![resultSHA1 isEqualToData:[NSData dataWithBytes:quickbrownsha1 length:sizeof(quickbrownsha1)]])
	{
		XCTFail(@"Wrong sha1 for quick brown fox:%@",resultSHA1);
	}
}
- (void)testExample3
{
	NSData *resultSHA1 = [[NSData data] sha1DataCompatible];
	uint8_t  	quickbrownsha1[] = { 0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09 };

	if(![resultSHA1 isEqualToData:[NSData dataWithBytes:quickbrownsha1 length:sizeof(quickbrownsha1)]])
	{
		XCTFail(@"Wrong sha1 for quick brown fox:%@",resultSHA1);
	}
}

@end
