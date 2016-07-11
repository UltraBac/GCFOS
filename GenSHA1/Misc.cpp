#include "stdafx.h"


void tohex_A(LPBYTE p, size_t len, char* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = p + len - 1;
		}
	else
		{
		in = p;
		}

	while(len--)
		{
		sprintf_s(out, 3, "%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}

void tobin_A(LPCSTR in, size_t len, UCHAR *p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}
}

// Unicode versions

void tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = (LPBYTE)p + len - 1;
		}
	else
		{
		in = (LPBYTE)p;
		}

	while(len--)
		{
		swprintf_s(out, 3, L"%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}
   
       
   
void tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (BYTE)(*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (BYTE)(*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}

}

   
       
   
     
   
 
 
 
             
    
 
     
