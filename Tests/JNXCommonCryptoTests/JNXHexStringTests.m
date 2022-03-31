//
//  JNXHexStringTests.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 3/25/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

#import "JNXHexStringTests.h"
#import "JNXCommonCrypto.h"

@implementation JNXHexStringTests


- (void)testExample1
{
	const char	*quickbrowntxt	 		= "The quick brown fox jumps over the lazy dog.";
	NSData 		*quickbrownTXTData		= [NSData dataWithBytes:quickbrowntxt length:strlen(quickbrowntxt)];
	NSString	*quickBrownHexString	= @"54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e";

	NSString	*hexEncoded = [quickbrownTXTData hexString];
	
	if(![hexEncoded isEqualToString:quickBrownHexString]) 							    XCTFail(@"Encoded Hex not matching");
	if(![[hexEncoded hexstringData] isEqualToData:quickbrownTXTData]) 				    XCTFail(@"Decoded Hex not matching");
	if(![[[hexEncoded uppercaseString] hexstringData] isEqualToData:quickbrownTXTData]) XCTFail(@"Decoded Hex not matching");

	if( ![[[NSData data] hexString] isEqualToString:@"" ])							    XCTFail(@"Encoded empty data not matching");
	if( ![[@""  hexstringData] isEqualToData:[NSData data]])						    XCTFail(@"Encoded empty data not matching");
}

- (void)testExample2
{
	for( int i=0; i< 1000; i++ )
	{
		NSData 	*randomData = [NSData randomDataWithLength:random()%1000];

		NSString *randomString = [randomData hexString];

		if( ![randomData isEqualToData:[randomString hexstringData]] )				            XCTFail(@"converted back and forth not correct");
		if( ![randomData isEqualToData:[[randomString uppercaseString] hexstringData]] )		XCTFail(@"converted back and forth not correct");
	}
}




@end
