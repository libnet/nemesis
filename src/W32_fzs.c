/*
 * $Id: W32_fzs.c,v 1.1.1.1 2003/10/31 21:29:38 jnathan Exp $
 *
 * Copyright (c) 1999, 2000
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(WIN32)
#include <stdio.h>
#include <signal.h>
#include <windows.h>

void* GetAdapterFromList(void* device,int index)
{
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	char* Adapter95;
	WCHAR* Adapter;
	int i;

	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)  // Windows '95
	{
		Adapter95=device;
		for(i=0;i<index-1;i++){
			while(*Adapter95++!=0);
			if(*Adapter95==0)return NULL; 
		}
		return	Adapter95;
	}
	else{
		Adapter=(WCHAR*)device;
		for(i=0;i<index-1;i++){
			while(*Adapter++!=0);
			if(*Adapter==0)return NULL; 
		}
		return	Adapter;
	}
	
}

void PrintDeviceList(const char* device)
{
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	const WCHAR* t;
	const char* t95;
	int i=0;
	int DescPos=0;
	char *Desc;
	int n=1;

	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)  // Windows '95
	{
		t95=(char*)device;

		while(*(t95+DescPos)!=0 || *(t95+DescPos-1)!=0){
			DescPos++;
		}

		Desc=(char*)t95+DescPos+1;
        printf("\nInterface\tDevice\t\t\t\t\tDescription\n-------------------------------------------\n");
		printf("%d ",n++);

		while (!(t95[i]==0 && t95[i-1]==0))
		{
			if (t95[i]==0){
				putchar(' ');
				putchar('(');
				while(*Desc!=0){
					putchar(*Desc);
					Desc++;
				}
				Desc++;
				putchar(')');
				putchar('\n');
			}
			else putchar(t95[i]);

			if((t95[i]==0) && (t95[i+1]!=0)){
				printf("%d ",n++);
			}

			i++;
		}
		putchar('\n');
	}
	
	else{		//Windows NT

		t=(WCHAR*)device;
		while(*(t+DescPos)!=0 || *(t+DescPos-1)!=0){
			DescPos++;
		}

		DescPos<<=1;
		Desc=(char*)t+DescPos+2;
        printf("\nInterface\tDevice\t\t\t\t\tDescription\n----------------------------------------------------------------------------\n");
		printf("%d ",n++);
		while (!(t[i]==0 && t[i-1]==0))
		{
			if (t[i]==0)
			{
				putchar(' ');
				putchar('(');
				while(*Desc!=0){
					putchar(*Desc);
					Desc++;
				}
				Desc++;
				putchar(')');
				putchar('\n');
			}
			else putchar(t[i]);

			if(t[i]==0 && t[i+1]!=0)printf("%d ",n++);

			i++;
		}
		putchar('\n');
	}
}
#endif /* WIN32 */
