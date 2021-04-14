#include <stdio.h>
#include <windows.h>

int main() {
    FILE *input_txt = NULL;
    FILE *output_txt = NULL;
    FILE *output_bin = NULL;

    input_txt = fopen("C:/Users/Desman/CLionProjects/MasterClass1/main.exe", "rb");

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, input_txt);

    if(dos_header.e_magic != 'ZM')
    {
        printf("IMAGE_DOS_HEADER signature is incorrect");
        return 0;
    }

    fseek(input_txt, dos_header.e_lfanew, 0);

    IMAGE_NT_HEADERS32 nt_headers;
    fread(&nt_headers, sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * 16, 1, input_txt);

    DWORD first_section = dos_header.e_lfanew + nt_headers.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);
    fseek(input_txt, first_section, 0);

    output_txt = fopen("C:/Users/Desman/CLionProjects/MasterClass1/output1.txt", "w");
    output_bin = fopen("C:/Users/Desman/CLionProjects/MasterClass1/output1.bin", "wb");
    fprintf(output_txt, "Address of entry point: %lu\n", nt_headers.OptionalHeader.AddressOfEntryPoint);
    for(int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER header;
        fread(&header, sizeof(IMAGE_SECTION_HEADER), 1, input_txt);
        char name[9] = {0};
        memcpy(name, header.Name, 8);
        fprintf(output_txt,"\nSection: %s\n", name);
        fprintf(output_txt, "Virtual size: %lx\n", header.Misc.VirtualSize);
        fprintf(output_txt, "Raw size: %lu\n", header.SizeOfRawData);
        fprintf(output_txt, "Virtual address: %lu\n", header.VirtualAddress);
        fprintf(output_txt, "Raw address: %lu\n", header.PointerToRawData);
        fprintf(output_txt, "Characteristics: ");
        if(header.Characteristics & IMAGE_SCN_MEM_READ)
            fprintf(output_txt, "R ");
        if(header.Characteristics & IMAGE_SCN_MEM_WRITE)
            fprintf(output_txt, "W ");
        if(header.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            fprintf(output_txt, "X ");
        if(header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
            fprintf(output_txt, "discardable ");
        if(header.Characteristics & IMAGE_SCN_MEM_SHARED)
            fprintf(output_txt, "shared");
        fprintf(output_txt,"\n");
        if(header.Characteristics & IMAGE_SCN_CNT_CODE){
            int last_el = ftell(input_txt);
            fseek(input_txt, header.PointerToRawData, 0);
            for (DWORD j =0; j < header.SizeOfRawData; j++) {
                fprintf(output_bin, "%X ", fgetc(input_txt));
            }
            fseek(input_txt, last_el,0);
        }

    }
    fclose(input_txt);
    fclose(output_txt);
    fclose(output_bin);

    return 0;
}
