//
//  NSData+reverseData.m
//  Untitled
//
//  Created by Patrick Stein on 11-07-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "NSData+reverseData.h"


@implementation  NSData(reverseData)

- (NSData *)reverseData
{
	
	NSUInteger		length			= [self length];
	uint8_t			*source			= (void*)[self bytes]+length-1;
	NSMutableData	*mutableData	= [NSMutableData dataWithLength:length];
	
	uint8_t	*destination	= (void *)[mutableData bytes];
	uint8_t	*end			= destination+length;
	while( destination < end )
	{
		*destination++ = *source--;
	}
	return mutableData;
}

@end
