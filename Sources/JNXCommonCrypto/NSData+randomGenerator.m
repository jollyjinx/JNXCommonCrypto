//
//  NSData+randomGenerator.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "NSData+randomGenerator.h"

@implementation NSData (randomGenerator)


+ (NSData *)randomIV
{
	return [self randomDataWithLength:[self randomIVLength]];
}
+ (NSData *)randomSalt
{
	return [self randomDataWithLength:[self randomSaltLength]];
}

+ (size_t)randomSaltLength
{
	return 20;
}
+ (size_t)randomIVLength
{
	return 8;
}

+ (NSData *)randomDataWithLength:(size_t)length;
{
	NSMutableData	*mutableData	= [NSMutableData dataWithLength:length];
    
	arc4random_buf((void *)[mutableData bytes], (int)length);
	
	return [mutableData copy];
}
@end
