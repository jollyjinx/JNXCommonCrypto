//
//  JNXBase64Test.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 3/18/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

#import "JNXBase64Test.h"
#import "JNXCommonCrypto.h"

@implementation JNXBase64Test


- (void)testExample1
{
	const char	*quickbrowntxt	 		= "The quick brown fox jumps over the lazy dog.";
	NSData 		*quickbrownTXTData		= [NSData dataWithBytes:quickbrowntxt length:strlen(quickbrowntxt)];
	NSString	*quickBrownBase64String	= @"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=";

	NSString	*base64Encoded = [quickbrownTXTData base64EncodedString];
	
	if(![base64Encoded isEqualToString:quickBrownBase64String]) 							XCTFail(@"Ecoded Base64 not matching");
	if(![[NSData dataFromBase64String:base64Encoded] isEqualToData:quickbrownTXTData]) 		XCTFail(@"Decoded Base64 not matching");
}


@end
