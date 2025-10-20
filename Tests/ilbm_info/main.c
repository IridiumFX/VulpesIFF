#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_Parser.h>

#include "ilbm_decoders.h"
#include "IlbmInfo.h"

// Helper function to print the decoded ILBM information.
static void print_ilbm_info(const struct IlbmInfo *info)
{
    if (!info) {
        printf("Failed to decode ILBM information.\n");
        return;
    }

    printf("--- ILBM Header (BMHD) ---\n");
    printf("  Dimensions: %u x %u\n", info->bmhd.w, info->bmhd.h);
    printf("  Bitplanes: %u\n", info->bmhd.nPlanes);
    printf("  Compression: %u\n", info->bmhd.compression);
    printf("  Masking: %u\n", info->bmhd.masking);
    printf("  Transparent Color: %u\n", info->bmhd.transparentColor);
    printf("  Aspect Ratio: %u:%u\n", info->bmhd.xAspect, info->bmhd.yAspect);

    if (info->palette_size > 0)
    {
        printf("\n--- Color Palette (CMAP) ---\n");
        printf("  Found %u colors:\n", info->palette_size);
        for (VPS_TYPE_16U i = 0; i < info->palette_size; ++i)
        {
            printf("    Color %3u: R=0x%02X, G=0x%02X, B=0x%02X\n", i, info->palette[i].r, info->palette[i].g, info->palette[i].b);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <filename.iff>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    int file_handle = open(filename, O_RDONLY | O_BINARY);
    if (file_handle < 0)
    {
        perror("Error opening file");
        return 1;
    }

    // 1. Create the parser factory.
    struct IFF_Parser *parser = 0;
    IFF_Parser_Allocate(&parser);
    IFF_Parser_Construct(parser);

    // 2. Register the application-specific decoders for ILBM.
    register_ilbm_decoders(parser);

    // 3. Attach the parser to the file to get a state object.
    struct IFF_Parser_State *state = 0;
    IFF_Parser_Attach(parser, file_handle, &state);

    // 4. Run the scan. This is the main parsing operation.
    printf("Scanning file: %s\n\n", filename);
    char result = IFF_Parser_Scan(parser, state);

    if (result)
    {
        printf("\nScan successful!\n\n");
        // 5. Retrieve the final assembled object from the parser state.
        struct IlbmInfo *info = state->final_entity;
        print_ilbm_info(info);
        // The application now owns the final_entity and must free it.
        if (info) free(info);
    }
    else
    {
        fprintf(stderr, "\nError: Failed to parse IFF file.\n");
    }

    // 6. Clean up all resources.
    IFF_Parser_State_Release(state);
    IFF_Parser_Release(parser);
    close(file_handle);

    return result ? 0 : 1;
}
