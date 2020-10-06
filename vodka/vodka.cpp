#include <string.h>
using namespace std;
#include <iostream>
#include <windows.h>
#include <fstream>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable : 4996 )

#define P2ALIGNUP(size, align) ( (((size) / (align)) + 1) * (align)  )

char* dumpMappedImg(char* buf) {
	PIMAGE_DOS_HEADER dosHdr = ((PIMAGE_DOS_HEADER)buf);
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(buf + dosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER stectionArr = (PIMAGE_SECTION_HEADER)((size_t)ntHdr + sizeof(IMAGE_NT_HEADERS));
	char *mappedImg = (char*)calloc(ntHdr->OptionalHeader.SizeOfImage, 1);
	memcpy(mappedImg, buf, ntHdr->OptionalHeader.SizeOfHeaders);
	for (size_t i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
		memcpy(mappedImg + stectionArr[i].VirtualAddress, buf + stectionArr[i].PointerToRawData, stectionArr[i].SizeOfRawData);
	return mappedImg;
}

BYTE* MapFileToMemory(LPCSTR filename, LONGLONG& filelen)
{
	FILE* fileptr;
	BYTE* buffer;
	printf("[+] income dotNet PE: %s\n", filename);
	fileptr = fopen(filename, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (BYTE*)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file

	return buffer;
}

struct STORAGESIGNATURE
{
	ULONG       lSignature;             // "Magic" signature.
	USHORT      iMajorVer;              // Major file version.
	USHORT      iMinorVer;              // Minor file version.
	ULONG       iExtraData;             // Offset to next structure of information 
	ULONG       iVersionString;         // Length of version string
};

struct STORAGEHEADER
{
	BYTE        fFlags;                 // STGHDR_xxx flags.
	BYTE        pad;
	USHORT      iStreams;               // How many streams are there.
};


struct STORAGESTREAM
{
public:
	ULONG       iOffset;                // Offset in file for this stream.
	ULONG       iSize;                  // Size of the file.
	char        rcName[32];  // Start of name, null terminated.
};

struct MDStreamHeader {
	DWORD Reserved;
	BYTE Major;
	BYTE Minor;
	BYTE Heaps;
	BYTE Rid;
	ULONGLONG MaskValid;
	ULONGLONG Sorted;
};

string* maskLookupTable = new string[64]{ 
	"Module",
	"TypeRef",
	"TypeDef",
	"FieldPtr",
	"Field",
	"MethmodPtr",
	"Method",
	"ParamPtr",
	"Param",
	"InterfaceImpl",
	"MemberRef",
	"Constant",
	"CustomAttribute",
	"FieldMarshal",
	"DeclSecurity",
	"ClassLayout",
	"FieldLayout",
	"StandAloneSig",
	"EventMap",
	"EventPtr",
	"Event",
	"PropertyMap",
	"PropertyPtr",
	"Property",
	"MethodSemantics",
	"MethodImpl",
	"ModuleRef",
	"TypeSpec",
	"ImplMap",
	"FieldRVA",
	"ENCLog",
	"ENCMap",
	"Assembly",
	"AssemblyProcessor",
	"AssemblyOS",
	"AssemblyRef",
	"AssemblyRefProcessor",
	"AssemblyRefOS",
	"File",
	"ExportedType",
	"ManifestResource",
	"NestedClass",
	"GenericParam",
	"MethodSpec",
	"GenericParamConstraint"
};


typedef struct Module_Struct {
	WORD    Generation;
	WORD    Name;   
	WORD    Mvid; 
	WORD    EncId; 
	WORD    EncBaseId; 
} METADATA_HEADER;

int main(int argc, char** argv)
{
	if (argc != 2) {
		printf("usage: vodka.exe [path/to/dotNet/file]\n");
		return 0;
	}
	LONGLONG peSize;
	BYTE* peData = MapFileToMemory(argv[1], peSize);
	char* dynImg = dumpMappedImg((char*)peData);

	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)dynImg;
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(dynImg + dosHdr->e_lfanew);

	auto clrInfo = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
	PIMAGE_COR20_HEADER clrHdr = (PIMAGE_COR20_HEADER)(dynImg + clrInfo.VirtualAddress);
	STORAGESIGNATURE* pMetaData = (STORAGESIGNATURE*)(dynImg + clrHdr->MetaData.VirtualAddress);
	STORAGEHEADER* pMetaDataHdr = (STORAGEHEADER*)((size_t)pMetaData + pMetaData->iVersionString + sizeof(STORAGESIGNATURE));
	bool validDotNet = !memcmp(&pMetaData->lSignature, "BSJB", 4);
	printf("[+] DotNet Header Verify: %s\n", validDotNet ? "True" : "False");

	char* szCLR = (char*)((size_t)&pMetaData->iVersionString + sizeof(pMetaData->iVersionString));
	printf("[+] CLR Requement: %s\n", szCLR);

	printf("[+] Decode DotNet Binary Stream...\n");
	MDStreamHeader* mdStream = NULL;
	STORAGESTREAM* stream = (STORAGESTREAM*)((size_t)pMetaDataHdr + sizeof(*pMetaDataHdr));
	char* ptrStreamStrings = 0;
	for (size_t i = 0; i < pMetaDataHdr->iStreams; i++)
	{
		printf("\t#%i found record  %s at %x [size = %i bytes.]\n", i, &stream->rcName, stream->iOffset, stream->iSize);

		if (!strcmp((char*)&stream->rcName, "#~"))
			mdStream = (MDStreamHeader*)((size_t)pMetaData + stream->iOffset);
		else if (!strcmp((char*)&stream->rcName, "#Strings"))
			ptrStreamStrings = (char *)pMetaData + stream->iOffset;

		size_t streamNameSize = P2ALIGNUP(strlen((char*)&stream->rcName), 4);
		stream = (STORAGESTREAM*)((size_t)&stream->rcName + streamNameSize);
	}
	
	printf("\n[+] Parse Table\n");
	int tableCount = 0;
	char* lookupTbArr = (char*)&mdStream->Sorted + sizeof(mdStream->Sorted);
	for (uint64_t i = 0; i < 45; i++) {
		if (mdStream->MaskValid & ((uint64_t)1 << (uint64_t)i)) {
			tableCount++;
			uint32_t itemCount = *(uint32_t*)(lookupTbArr);
			cout << "\tfound table#" << i << " - " << maskLookupTable[i] << " [count = " << itemCount << "]" << endl;
			lookupTbArr += sizeof(uint32_t);
		}
	}

	Module_Struct p = *(Module_Struct*)lookupTbArr;
	printf("\n[+] Detect Compiled .NET Module [%s]\n", (ptrStreamStrings + p.Name));


}
