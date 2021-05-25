#pragma once
/*
	作者：windpiaoxue
	联系方式：2977493715
*/




void* dxgi_create(void);
void dxgi_destroy(void*);
int dxgi_get_size(void*);
int dxgi_get_width(void*);
int dxgi_get_height(void*);
bool dxgi_get_frame(void*, char*);
