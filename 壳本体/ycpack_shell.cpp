// ycpack_shell.cpp : Defines the entry point for the console application.
//

#include "StdAfx.h"
#include "head.h"
#define  MY_DEBUG
char g_NameOfNewSectionHeader[] = {'Y', 'U', 'C', 'H', 'U'};

int main()
{
    //--------------------------------------解密过程--------------------------------------
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS32 pNTHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD file_size = 0;

    //获取当前程序运行路径
    char FilePathSelf[0x100] = {0};
    GetModuleFileName(NULL, FilePathSelf, 0x100);

    // 1、读取当前壳子程序本身 数据
    file_size = ReadPEFile(FilePathSelf, pFileBuffer, pDosHeader, pNTHeader,
                           pSectionHeader);

    // 2、解密源文件,获取源文件的imagebase sizeofimage数据
    LPVOID pFileBufferSrc = NULL;
    DWORD dwBufferImageBaseSrc = 0;
    DWORD dwBufferSizeOfImageSrc = 0;
    GetSrcDataFromShell(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
                        pFileBufferSrc, dwBufferImageBaseSrc,
                        dwBufferSizeOfImageSrc);
	MY_ASSERT(pFileBufferSrc);
#ifdef MY_DEBUG
	cout << hex;
	cout << "源文件MZ头：" <<  *((PWORD)pFileBufferSrc) << endl;
	cout << "源文件ImageBase：" << dwBufferImageBaseSrc << endl;
	cout << "源文件SizeOfImage：" << dwBufferSizeOfImageSrc << endl;
#endif

	// 3、拉伸PE  pImageBufferSrc
	PVOID pImageBufferSrc = NULL;
	CopyFileBufferToImageBuffer(pFileBufferSrc, &pImageBufferSrc);

    // 4、以挂起方式运行壳程序进程
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);
	::CreateProcess(FilePathSelf, NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
#ifdef MY_DEBUG
	printf("error is %d\n", GetLastError());
#endif

	DWORD dwImageBaseShell = pNTHeader->OptionalHeader.ImageBase; // 获取壳子程序自身的imagebase

    // 5、卸载外壳程序的文件镜像
	typedef long NTSTATUS;
	typedef NTSTATUS(__stdcall * pfnZwUnmapViewOfSection)(unsigned long ProcessHandle, unsigned long BaseAddress);
	
	pfnZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
	HMODULE hModule = LoadLibrary("ntdll.dll");
	if (hModule)
	{
		ZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hModule, "ZwUnmapViewOfSection");
		if (ZwUnmapViewOfSection)
		{
			if (ZwUnmapViewOfSection((unsigned long)pi.hProcess, dwImageBaseShell))
			{ // 卸载掉 壳子程序自身的ImageBase 地址
				printf("ZwUnmapViewOfSection success\n");
			}
		}
		FreeLibrary(hModule);
	}

    // 6、在指定的位置(src的ImageBase)申请指定大小(src的SizeOfImage)的内存(VirtualAllocEx)
	LPVOID status = ::VirtualAllocEx(pi.hProcess, (LPVOID)dwBufferImageBaseSrc, 
		dwBufferSizeOfImageSrc, 
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (status == NULL)
	{
		printf("error is %d\n", GetLastError());
		EXIT_ERROR("使用VirtualAllocEx申请内存时失败");
	}
	else
	{
#ifdef MY_DEBUG
		printf("VirtualAllocEx返回值为：%x\n", status);
#endif
		//7、如果成功，将Src的PE文件拉伸 复制到该空间中
		if (WriteProcessMemory(pi.hProcess, (LPVOID)dwBufferImageBaseSrc, pImageBufferSrc, dwBufferSizeOfImageSrc, NULL) == 0)
		{
			printf("error: \n", GetLastError());
			EXIT_ERROR("WriteProcessMemory failure");
		}
	}

    // TODO: 8、如果申请空间失败，但有重定位表：在任意位置申请空间，然后将PE文件拉伸、复制、修复重定位表。

    // TODO: 9、如果第6步申请空间失败，并且还没有重定位表，直接返回：失败.

	// 10、修改外壳程序的Context:
	CONTEXT cont;
	cont.ContextFlags = CONTEXT_FULL;
	::GetThreadContext(pi.hThread, &cont);
	
	DWORD dwEntryPoint = GetOep(pFileBufferSrc);	// get oep
	cont.Eax = dwEntryPoint + dwBufferImageBaseSrc; // set origin oep
	
	DWORD theOep = cont.Ebx + 8;
	DWORD dwBytes = 0;
	WriteProcessMemory(pi.hProcess, &theOep, &dwBufferImageBaseSrc, 4, &dwBytes);
	
	SetThreadContext(pi.hThread, &cont);
	//记得恢复线程
	ResumeThread(pi.hThread);
	ExitProcess(0);
	getchar();
    return 0;
}
