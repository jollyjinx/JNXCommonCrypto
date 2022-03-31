//
//  NSData+PEM.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-13.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//
#import <Foundation/Foundation.h>

#import "NSData+PEM.h"
#import "NSData+Base64.h"

@implementation NSData (PEM)

- (NSData *)dataFromPEMSection;
{
	NSString *PEMString = [[NSString alloc] initWithData:self encoding:NSUTF8StringEncoding];
	
	NSRange beginRange 	= [PEMString rangeOfString:@"-----BEGIN "];
	NSRange endRange	= [PEMString rangeOfString:@"\n-----END "];
	
	if( beginRange.location != NSNotFound && endRange.location != NSNotFound && beginRange.location<endRange.location )
	{
		NSUInteger 	begin 		= beginRange.location+beginRange.length;
		NSRange 	realBegin 	= [PEMString rangeOfString:@"-----\n" options:NSLiteralSearch range:NSMakeRange(begin,(endRange.location-begin))];
		
		if( realBegin.location != NSNotFound )
		{
			NSString 	*base64String = [PEMString substringWithRange:NSMakeRange(realBegin.location+realBegin.length,endRange.location-(realBegin.location+realBegin.length))];
			NSData		*dataToReturn = [NSData dataFromBase64String:base64String];
			
			return dataToReturn;
		}	
	}
	return self;
}
- (NSData *)dataByAddingPEMPrivateHeader
{
	return [[NSString stringWithFormat:@"-----BEGIN PRIVATE KEY-----\n%@\n-----END PRIVATE KEY-----\n",[self base64EncodedString]] dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSData *)dataByAddingPEMPublicHeader;
{
	return [[NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----\n",[self base64EncodedString]] dataUsingEncoding:NSUTF8StringEncoding];
}


@end
