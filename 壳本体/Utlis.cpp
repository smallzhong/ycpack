#include "StdAfx.h"
#include "head.h"

extern char g_NameOfNewSectionHeader[];

DWORD GetOep(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;
	PIMAGE_BASE_RELOCATION pRelocationDirectory = NULL;
	
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	return pImageOptionalHeader->AddressOfEntryPoint;
}

DWORD GetRelocationTable(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;
	DWORD res = 0;
	
	DWORD NewLength = 0;
	PVOID LastSection = NULL;
	PVOID CodeSection = NULL;
	PVOID AddressOfSectionTable = NULL;
	DWORD FOA = 0;
	
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	return pImageOptionalHeader->DataDirectory[5].VirtualAddress;
}

DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer, PVOID *pImageBuffer)
{
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	DWORD ImageBufferSize = 0;
	DWORD i = 0;
	
	// DOS头
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	// 标准PE
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	
	// 可选PE
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	
	//节表组
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	//获取ImageBufffer的内存大小
	ImageBufferSize = pImageOptionalHeader->SizeOfImage;
	
	//为pImageBuffer分配内存空间
	*pImageBuffer = (PVOID)malloc(ImageBufferSize);
	
	if (*pImageBuffer == NULL)
	{
		printf("malloc failed");
		return -1;
	}
	
	//清零
	memset(*pImageBuffer, 0, ImageBufferSize);
	
	// 拷贝头+节表
	memcpy(*pImageBuffer, pFileBuffer, pImageOptionalHeader->SizeOfHeaders);
	
	//循环拷贝节表
	for (i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		memcpy(
			(PVOID)((DWORD)*pImageBuffer + pImageSectionHeaderGroup[i].VirtualAddress), // 要拷贝的位置 ImageBuffer中的每个节数据的偏移位置
			(PVOID)((DWORD)pFileBuffer + pImageSectionHeaderGroup[i].PointerToRawData), // 被拷贝的位置是 Filebuffer中的每个节数据的偏移位置
			pImageSectionHeaderGroup[i].SizeOfRawData									// 被拷贝的大小为 每个节数据的文件对齐大小
			);
	}
	
	return 0;
}

DWORD GetSrcDataFromShell(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
                          PIMAGE_NT_HEADERS32 pNTHeader,
                          PIMAGE_SECTION_HEADER pSectionHeader,
                          LPVOID& pFileBuffer_Src, DWORD& dwBufferImageBaseSrc,
                          DWORD& dwBufferSizeOfImageSrc)
{
    PIMAGE_DOS_HEADER pDosHeader_src = NULL;
    PIMAGE_NT_HEADERS32 pNTHeader_src = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader_src = NULL;
    DWORD numOfSec = 0;
    // (1) 定位到SHELL文件的最后一个节
    numOfSec = pNTHeader->FileHeader.NumberOfSections;
    pFileBuffer_Src =
        (LPVOID)((PBYTE)pFileBuffer +
                 ((pSectionHeader + numOfSec - 1)->PointerToRawData));
	MY_ASSERT(pFileBuffer_Src);
	
	// 设置各种指针
	pDosHeader_src = (PIMAGE_DOS_HEADER)pFileBuffer_Src;
	MY_ASSERT(pDosHeader_src);
	MY_ASSERT((pDosHeader_src->e_magic == IMAGE_DOS_SIGNATURE));

	pNTHeader_src = (PIMAGE_NT_HEADERS32)((PBYTE)pDosHeader_src + pDosHeader_src->e_lfanew);
	if (pNTHeader->FileHeader.SizeOfOptionalHeader != 0xe0)
		EXIT_ERROR("this is not a 32-bit executable file.");

	pSectionHeader_src = (PIMAGE_SECTION_HEADER)(
		(PBYTE)pNTHeader_src + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader_src->FileHeader.SizeOfOptionalHeader);

    // TODO: 解密

	// get SizeOfImage
	dwBufferSizeOfImageSrc = pNTHeader_src->OptionalHeader.SizeOfImage;
	
	// get ImageBase
	dwBufferImageBaseSrc = pNTHeader_src->OptionalHeader.ImageBase;

    return 0;
}

DWORD ReadPEFile(IN LPSTR file_in, OUT LPVOID& pFileBuffer,
                 PIMAGE_DOS_HEADER& pDosHeader, PIMAGE_NT_HEADERS32& pNTHeader,
                 PIMAGE_SECTION_HEADER& pSectionHeader)
{
    FILE* fp;
    fp = fopen(file_in, "rb");
    if (!fp)
        EXIT_ERROR("fp == NULL!");
    DWORD file_size = 0;
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    LPVOID t = malloc(file_size);
    if ((fread(t, file_size, 1, fp) != 1) || t == NULL)
        EXIT_ERROR("fread error or malloc error!");

    pFileBuffer = t;
    MY_ASSERT(pFileBuffer);

    pDosHeader = (PIMAGE_DOS_HEADER)(pFileBuffer);
    MY_ASSERT(pDosHeader);
    MY_ASSERT((pDosHeader->e_magic == IMAGE_DOS_SIGNATURE));

    pNTHeader =
        (PIMAGE_NT_HEADERS32)((PBYTE)pFileBuffer + pDosHeader->e_lfanew);
    if (pNTHeader->FileHeader.SizeOfOptionalHeader != 0xe0)
        EXIT_ERROR("this is not a 32-bit executable file.");

    pSectionHeader = (PIMAGE_SECTION_HEADER)(
        (PBYTE)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
        sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
    fclose(fp);
    return file_size;
}
