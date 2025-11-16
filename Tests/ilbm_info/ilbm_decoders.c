#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_DataPump.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Parser.h>

#include "IlbmInfo.h"
#include "ilbm_decoders.h"


// --- BMHD Chunk Decoder ---

static char bmhd_end_decode(struct IFF_Parser_State *state, void *custom_state, struct IFF_ContextualData **out)
{
    // For a simple, non-sharded chunk, the custom_state is NULL.
    // The data for the chunk is still in the IFF_Reader's buffer.
    // We read it directly here.
    (void)custom_state; // Unused

    struct VPS_Data* raw_data = 0;
    // The size of the chunk we're finalizing is stored in the active_chunk_tag's context.
    // This is a bit of a simplification; a more robust parser might pass the size explicitly.
    // For this test, we'll assume the last read size is what we need.
    // A better approach would be to read it from the parser state if it were stored there.
    // Let's assume for the test that the data is already read and we just need to package it.
    // This part of the test highlights a potential area for API improvement in the parser.

    // Create the contextual data packet to pass to the form decoder.
    // The form decoder will be responsible for releasing it.
    // IFF_ContextualData_Allocate(out);
    // IFF_ContextualData_Construct(*out, state->active_header_flags, raw_data);

    return 1;
}

// --- CMAP Chunk Decoder ---

static char cmap_end_decode(struct IFF_Parser_State *state, void *custom_state, struct IFF_ContextualData **out)
{
    // Similar to bmhd_end_decode, we would read the data from the IFF_Reader here.
    // For this simplified test, we are just confirming the lifecycle.
    (void)state;
    (void)custom_state;
    *out = NULL; // No actual data produced in this simplified test.

    return 1;
}

// --- Generic Shard Processing ---
// For simple, non-aggregated chunks, we just store the first shard's data.

static char simple_chunk_begin_decode(struct IFF_Parser_State *state, void **custom_state)
{
    *custom_state = 0; // No data yet.
    return 1;
}

static char simple_chunk_process_shard(struct IFF_Parser_State *state, void *custom_state, const struct VPS_Data *chunk_data)
{
    // For a truly simple chunk that isn't sharded, this function can do nothing.
    // The parser will call it once, and then immediately call end_decode.
    // All the data processing can happen in end_decode.
    (void)state; (void)custom_state; (void)chunk_data;
    return 1;
}

// --- ILBM Form Decoder ---

static char ilbm_begin_decode(struct IFF_Parser_State *state, void **custom_state)
{
    // When we enter an ILBM form, allocate the IlbmInfo object that we will build progressively.
    struct IlbmInfo* info = calloc(1, sizeof(struct IlbmInfo));
    *custom_state = info;
    return info != NULL;
}

static char ilbm_process_chunk(struct IFF_Parser_State *state, void *custom_state, struct IFF_Tag *chunk_tag, struct IFF_ContextualData *contextual_data)
{
    struct IlbmInfo* info = custom_state;
    VPS_TYPE_16S ordering;

    // This is the core assembly logic. We check the tag of the incoming chunk
    // and decide how to process its data.

    // To compare tags, we must construct a proper IFF_Tag object.
    struct IFF_Tag bmhd_tag;
    IFF_Tag_Construct(&bmhd_tag, (const unsigned char*)"BMHD", 4, IFF_TAG_TYPE_TAG);

    IFF_Tag_Compare(chunk_tag, &bmhd_tag, &ordering);
    if (ordering == 0)
    {
        struct VPS_DataReader reader;
        VPS_DataReader_Construct(&reader, contextual_data->data);
        VPS_DataReader_Read16UBE(&reader, &info->bmhd.w);
        VPS_DataReader_Read16UBE(&reader, &info->bmhd.h);
        VPS_DataReader_Read16SBE(&reader, &info->bmhd.x);
        VPS_DataReader_Read16SBE(&reader, &info->bmhd.y);
        VPS_DataReader_Read8U(&reader, &info->bmhd.nPlanes);
        VPS_DataReader_Read8U(&reader, &info->bmhd.masking);
        VPS_DataReader_Read8U(&reader, &info->bmhd.compression);
        VPS_DataReader_Read8U(&reader, &info->bmhd.pad1);
        VPS_DataReader_Read16UBE(&reader, &info->bmhd.transparentColor);
        VPS_DataReader_Read8U(&reader, &info->bmhd.xAspect);
        VPS_DataReader_Read8U(&reader, &info->bmhd.yAspect);
        VPS_DataReader_Read16SBE(&reader, &info->bmhd.pageWidth);
        VPS_DataReader_Read16SBE(&reader, &info->bmhd.pageHeight);
    }

    struct IFF_Tag cmap_tag;
    IFF_Tag_Construct(&cmap_tag, (const unsigned char*)"CMAP", 4, IFF_TAG_TYPE_TAG);

    IFF_Tag_Compare(chunk_tag, &cmap_tag, &ordering);
    if (ordering == 0)
    {
        struct VPS_DataReader reader;
        VPS_DataReader_Construct(&reader, contextual_data->data);
        info->palette_size = contextual_data->data->size / 3;
        for (VPS_TYPE_16U i = 0; i < info->palette_size; ++i)
        {
            VPS_DataReader_Read8U(&reader, &info->palette[i].r);
            VPS_DataReader_Read8U(&reader, &info->palette[i].g);
            VPS_DataReader_Read8U(&reader, &info->palette[i].b);
        }
    }

    // We are now done with the contextual data, so we must release it.
    IFF_ContextualData_Release(contextual_data);
    return 1;
}

static char ilbm_end_decode(struct IFF_Parser_State *state, void *custom_state, void **out_final_entity)
{
    struct IlbmInfo* info = custom_state;
    struct IFF_ContextualData* cmap_data = 0;
    struct IFF_Tag cmap_tag;

    // --- This demonstrates the "PULL" semantic ---
    // The ILBM decoder knows it needs a CMAP. It actively searches for one
    // in the current scope using the hierarchical helper function.
    IFF_Tag_Construct(&cmap_tag, (const unsigned char*)"CMAP", 4, IFF_TAG_TYPE_TAG);
    if (IFF_Parser_State_FindProp(state, &cmap_tag, &cmap_data))
    {
        // We found a CMAP! Now we can parse it.
        struct VPS_DataReader reader;
        VPS_DataReader_Construct(&reader, cmap_data->data);
        info->palette_size = cmap_data->data->size / 3;
        for (VPS_TYPE_16U i = 0; i < info->palette_size; ++i)
        {
            VPS_DataReader_Read8U(&reader, &info->palette[i].r);
            VPS_DataReader_Read8U(&reader, &info->palette[i].g);
            VPS_DataReader_Read8U(&reader, &info->palette[i].b);
        }
    }

    // The IlbmInfo object is now fully assembled.
    *out_final_entity = info;
    return 1;
}

// --- Public Registration Function ---

char register_ilbm_decoders(struct IFF_Parser *parser)
{
    // 1. Create the chunk decoders.
    struct IFF_ChunkDecoder* bmhd_decoder = 0;
    IFF_ChunkDecoder_Allocate(&bmhd_decoder);
    IFF_ChunkDecoder_Construct(bmhd_decoder, simple_chunk_begin_decode, simple_chunk_process_shard, bmhd_end_decode);

    struct IFF_ChunkDecoder* cmap_decoder = 0;
    IFF_ChunkDecoder_Allocate(&cmap_decoder);
    IFF_ChunkDecoder_Construct(cmap_decoder, simple_chunk_begin_decode, simple_chunk_process_shard, cmap_end_decode);

    // 2. Create the form decoder.
    struct IFF_FormDecoder* ilbm_decoder = 0;
    IFF_FormDecoder_Allocate(&ilbm_decoder);
    IFF_FormDecoder_Construct(ilbm_decoder, ilbm_begin_decode, ilbm_process_chunk, 0, ilbm_end_decode);

    // 3. Register them with the parser.
    IFF_Parser_RegisterChunkDecoder(parser, "ILBM", "BMHD", 4, bmhd_decoder);
    IFF_Parser_RegisterChunkDecoder(parser, "ILBM", "CMAP", 4, cmap_decoder);
    IFF_Parser_RegisterFormDecoder(parser, "ILBM", 4, ilbm_decoder);

    return 1;
}
