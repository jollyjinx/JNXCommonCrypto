//
//  NSString+hexString.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-27.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "NSString+hexString.h"

@implementation NSString (hexString)

- (NSData *)hexstringData;
{
    NSData		*utf8Data 	= [self dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger	utf8length	= [utf8Data length];
    
    
    if( !utf8length || (utf8length & 0x1) )
    {
    	return [NSData data];
    }
    NSData 		*outputData		= [NSMutableData dataWithLength:utf8length/2];

    uint8_t		*buffer			= (uint8_t*)[utf8Data bytes];
    uint8_t		*outputbuffer	= (uint8_t*)[outputData bytes];
    
    uint8_t		intermediate = 0;
    for( NSUInteger i=0; i<utf8length; i++ )
    {
    	uint8_t	buffervalue = buffer[i];
        uint8_t	currentnibble;
        
    	switch( buffervalue )
        {
        	case '0'...'9'	:	currentnibble = buffervalue-'0';break;
            case 'a'...'f'	:	currentnibble = 0xA+buffervalue-'a';break;
            case 'A'...'F'	:	currentnibble = 0xA+buffervalue-'A';break;
            default:	return [NSData data];
        }
        
        if( i & 0x1 )
        {
        	outputbuffer[i/2] = intermediate|currentnibble;
            intermediate = 0;
        }
        else
        {
        	intermediate = currentnibble << 4;
        }
   }
    return [outputData copy];
}


@end

@implementation NSData (hexString)


- (NSString *)hexString;
{
    NSUInteger	length 	= [self length];
    uint8_t		*buffer	= (uint8_t*)[self bytes];

	uint8_t 	*hexstringbuffer 	= malloc((length*2)+1);
	uint8_t		*currentnibble		= hexstringbuffer;
    for(NSUInteger i=0; i<length ; i++)
    {
		*currentnibble++	= "0123456789abcdef"[((buffer[i]>>4)&0xF)];
		*currentnibble++	= "0123456789abcdef"[(buffer[i]    &0xF)];
    }
	*currentnibble=0;
	NSString *newString = [NSString stringWithUTF8String:(const char *)hexstringbuffer];
	free( (void *)hexstringbuffer);
    return newString;
}


@end
