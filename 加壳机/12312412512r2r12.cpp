#include "StdAfx.h"
#include "head.h"

int main()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	LPVOID pFileBuffer_src = NULL;
	PIMAGE_DOS_HEADER pDosHeader_src = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader_src = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader_src = NULL;

	char file_path_shell[256];
	char file_path_src[256];
	memset(file_path_shell, 0, 256);
	memset(file_path_src, 0, 256);

	printf("请输入壳程序的位置：");
	scanf("%s", file_path_shell);
	printf("请输入源程序的位置：");
	scanf("%s", file_path_src);

	DWORD file_size = ReadPEFile(file_path_shell, pFileBuffer, pDosHeader,
		pNTHeader, pSectionHeader);

	// 读取源文件
	DWORD file_size_src = ReadPEFile(file_path_src, pFileBuffer_src, pDosHeader_src,
		pNTHeader_src, pSectionHeader_src);

	// 新增节
	LPVOID pNewFileBuffer = NULL;
	AddNewSec(&pNewFileBuffer, pFileBuffer, pDosHeader, pNTHeader, pSectionHeader, file_size, file_size_src);
	file_size += file_size_src; // 更新文件大小
	pFileBuffer = pNewFileBuffer;
	// 复制到后面
	memcpy(
		(LPVOID)((PBYTE)pFileBuffer + file_size - file_size_src),
		pFileBuffer_src,
		file_size_src
		);

	char file_path_out[256];
	memset(file_path_out, 0, 256);
	printf("加壳已完成，请输入要保存的位置：");
	scanf("%s", file_path_out);
	FILE* fp_out;
	fp_out = fopen(file_path_out, "wb");
	MY_ASSERT(fp_out);
	fwrite(pFileBuffer, file_size, 1, fp_out);
	fclose(fp_out);
}

void AddNewSec(OUT LPVOID* pNewFileBuffer, IN LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, DWORD file_size, DWORD dwAddSize)
{
	PIMAGE_FILE_HEADER pImageFileHeader =
		(PIMAGE_FILE_HEADER)((PBYTE)pDosHeader + pDosHeader->e_lfanew + 4);

	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)(
		(PBYTE)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));

	if (((PBYTE)pImageOptionalHeader->SizeOfHeaders -
		((PBYTE)pDosHeader->e_lfanew + IMAGE_SIZEOF_FILE_HEADER +
			pImageFileHeader->SizeOfOptionalHeader +
			40 * pImageFileHeader->NumberOfSections)) < 80)
		EXIT_ERROR("空间不足，新增节表失败！");

	DWORD numOfSec = pImageFileHeader->NumberOfSections;
	// 1) 添加一个新的节表(可以copy一份)
	memcpy(
		(LPVOID)(pSectionHeader + numOfSec), // 需要新增的位置
		(LPVOID)(pSectionHeader), // 第一个节
		sizeof(IMAGE_SECTION_HEADER)
	); // 将第一个节（代码节）拷贝

	// 2) 在新增节后面 填充一个节大小的000
	memset((LPVOID)(pSectionHeader + numOfSec + 1), 0, sizeof(IMAGE_SECTION_HEADER));


	// 3) 修改PE头中节的数量
	pImageFileHeader->NumberOfSections += 1;

	// 4) 修改sizeOfImage的大小
	pImageOptionalHeader->SizeOfImage += 0x1000;

	// 5）修正新增节表的属性
	// 修改该节表的名字
	memcpy((LPVOID)(pSectionHeader + numOfSec), g_NameOfNewSectionHeader, sizeof(g_NameOfNewSectionHeader));
	// 修改该节表中其他必要属性
	(pSectionHeader + numOfSec)->Misc.VirtualSize = 0x1000; // 对齐前的大小，设为1000即可
	// 根据前一个节表的属性修改virtualAddress
	DWORD t_Add = 0; // (pSectionHeader + numOfSec - 1)->VirtualAddress 加上 t_Add 为VirtualAddress

	if ((pSectionHeader + numOfSec - 1)->Misc.VirtualSize < (pSectionHeader + numOfSec - 1)->SizeOfRawData)
	{ // 如果VirtualSize小于SizeOfRawData
		t_Add = (pSectionHeader + numOfSec - 1)->SizeOfRawData;
	}
	else
	{
		if (((pSectionHeader + numOfSec - 1)->Misc.VirtualSize % 0x1000) == 0) // 如果其能被0x1000整除
			t_Add = (pSectionHeader + numOfSec - 1)->Misc.VirtualSize;
		else
			t_Add = ((((pSectionHeader + numOfSec - 1)->Misc.VirtualSize / 0x1000) + 1)) * 0x1000;
	}
	MY_ASSERT(t_Add);
	(pSectionHeader + numOfSec)->VirtualAddress = (pSectionHeader + numOfSec - 1)->VirtualAddress
		+ t_Add;
	// 修改sizeofRawData
	(pSectionHeader + numOfSec)->SizeOfRawData = 0x1000;
	// 更新PointerToRawData
	(pSectionHeader + numOfSec)->PointerToRawData = (pSectionHeader + numOfSec - 1)->PointerToRawData +
		(pSectionHeader + numOfSec - 1)->SizeOfRawData;
	// (pSectionHeader + numOfSec)->Characteristics = (pSectionHeader->Characteristics | (pSectionHeader + numOfSec - 1)->Characteristics);

	// 6) 在原有数据的最后，新增一个节的数据(内存对齐的整数倍) (复制到新的LPVOID中去)
	*pNewFileBuffer = malloc(file_size + dwAddSize);
	memcpy(*pNewFileBuffer, pFileBuffer, file_size);
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

DWORD RVA_TO_FOA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD RVA)
{
	if (RVA < pNTHeader->OptionalHeader.SizeOfHeaders)
		return RVA;

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (RVA >= pSectionHeader[i].VirtualAddress &&
			RVA < pSectionHeader[i].VirtualAddress +
			pSectionHeader[i].Misc.VirtualSize)
		{
			return (RVA - pSectionHeader[i].VirtualAddress +
				pSectionHeader[i].PointerToRawData);
		}
	}

	EXIT_ERROR("rva to foa failure!");
}

DWORD FOA_TO_RVA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD FOA)
{
	if (FOA < pNTHeader->OptionalHeader.SizeOfHeaders)
		return FOA;

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (FOA >= pSectionHeader[i].PointerToRawData &&
			FOA < pSectionHeader[i].PointerToRawData +
			pSectionHeader[i].Misc.VirtualSize)
		{
			return (FOA - pSectionHeader[i].PointerToRawData +
				pSectionHeader[i].VirtualAddress);
		}
	}

	EXIT_ERROR("foa to rva error!");
}