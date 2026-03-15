#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Parser_Factory.h>

#include "ILBM/ILBM_Types.h"
#include "ILBM/ILBM_Decompression.h"
#include "ILBM/ILBM_Conversion.h"
#include "ILBM/ILBM_Codec.h"

/* ================================================================== */
/* Generic passthrough ChunkDecoder                                   */
/* Accumulates shard data into a single VPS_Data, wraps in Context.   */
/* ================================================================== */

struct PassthroughState
{
	struct VPS_Data* accumulated;
};

static char passthrough_begin(struct IFF_Parser_State* state, void** custom_state)
{
	(void)state;
	struct PassthroughState* ps = calloc(1, sizeof(struct PassthroughState));
	if (!ps) return 0;
	*custom_state = ps;
	return 1;
}

static char passthrough_shard(struct IFF_Parser_State* state, void* custom_state, const struct VPS_Data* chunk_data)
{
	(void)state;
	struct PassthroughState* ps = (struct PassthroughState*)custom_state;
	if (!ps || !chunk_data || chunk_data->size == 0) return 1;

	if (!ps->accumulated)
	{
		VPS_Data_Clone(&ps->accumulated, (struct VPS_Data*)chunk_data, 0, chunk_data->size);
	}
	else
	{
		/* Append. */
		VPS_TYPE_SIZE old_size = ps->accumulated->size;
		VPS_TYPE_SIZE new_size = old_size + chunk_data->size;
		VPS_TYPE_8U* new_buf = realloc(ps->accumulated->bytes, new_size);
		if (!new_buf) return 0;
		memcpy(new_buf + old_size, chunk_data->bytes, chunk_data->size);
		ps->accumulated->bytes = new_buf;
		ps->accumulated->size = new_size;
		ps->accumulated->limit = new_size;
	}

	return 1;
}

static char passthrough_end(struct IFF_Parser_State* state, void* custom_state, struct IFF_ContextualData** out)
{
	(void)state;
	struct PassthroughState* ps = (struct PassthroughState*)custom_state;
	if (!ps || !out) return 0;

	if (ps->accumulated)
	{
		union IFF_Header_Flags flags;
		flags.as_int = 0;
		IFF_ContextualData_Allocate(out);
		IFF_ContextualData_Construct(*out, flags, ps->accumulated);
		ps->accumulated = NULL; /* Ownership transferred. */
	}
	else
	{
		*out = NULL;
	}

	free(ps);
	return 1;
}

static char create_passthrough_decoder(struct IFF_ChunkDecoder** dec)
{
	if (!IFF_ChunkDecoder_Allocate(dec)) return 0;
	IFF_ChunkDecoder_Construct(*dec, passthrough_begin, passthrough_shard, passthrough_end);
	return 1;
}

/* ================================================================== */
/* ILBM FormDecoder                                                   */
/* ================================================================== */

static char ilbm_begin(struct IFF_Parser_State* state, void** custom_state)
{
	(void)state;
	struct ILBM_State* s = calloc(1, sizeof(struct ILBM_State));
	if (!s) return 0;
	*custom_state = s;
	return 1;
}

static char ilbm_process_chunk
(
	struct IFF_Parser_State* state,
	void* custom_state,
	struct IFF_Tag* chunk_tag,
	struct IFF_ContextualData* cd
)
{
	(void)state;
	struct ILBM_State* s = (struct ILBM_State*)custom_state;
	if (!s) return 0;

	VPS_TYPE_16S ordering;

	/* BMHD */
	{
		struct IFF_Tag tag;
		IFF_Tag_Construct(&tag, (const unsigned char*)"BMHD", 4, IFF_TAG_TYPE_TAG);
		IFF_Tag_Compare(chunk_tag, &tag, &ordering);
		if (ordering == 0 && cd && cd->data)
		{
			struct VPS_DataReader reader;
			VPS_DataReader_Construct(&reader, cd->data);
			VPS_DataReader_Read16UBE(&reader, &s->bmhd.w);
			VPS_DataReader_Read16UBE(&reader, &s->bmhd.h);
			VPS_DataReader_Read16SBE(&reader, &s->bmhd.x);
			VPS_DataReader_Read16SBE(&reader, &s->bmhd.y);
			VPS_DataReader_Read8U(&reader, &s->bmhd.nPlanes);
			VPS_DataReader_Read8U(&reader, &s->bmhd.masking);
			VPS_DataReader_Read8U(&reader, &s->bmhd.compression);
			VPS_DataReader_Read8U(&reader, &s->bmhd.pad1);
			VPS_DataReader_Read16UBE(&reader, &s->bmhd.transparentColor);
			VPS_DataReader_Read8U(&reader, &s->bmhd.xAspect);
			VPS_DataReader_Read8U(&reader, &s->bmhd.yAspect);
			VPS_DataReader_Read16SBE(&reader, &s->bmhd.pageWidth);
			VPS_DataReader_Read16SBE(&reader, &s->bmhd.pageHeight);
			s->has_bmhd = 1;
			IFF_ContextualData_Release(cd);
			return 1;
		}
	}

	/* CMAP */
	{
		struct IFF_Tag tag;
		IFF_Tag_Construct(&tag, (const unsigned char*)"CMAP", 4, IFF_TAG_TYPE_TAG);
		IFF_Tag_Compare(chunk_tag, &tag, &ordering);
		if (ordering == 0 && cd && cd->data)
		{
			s->palette_size = (VPS_TYPE_16U)(cd->data->size / 3);
			if (s->palette_size > ILBM_MAX_PALETTE) s->palette_size = ILBM_MAX_PALETTE;
			struct VPS_DataReader reader;
			VPS_DataReader_Construct(&reader, cd->data);
			for (VPS_TYPE_16U i = 0; i < s->palette_size; i++)
			{
				VPS_DataReader_Read8U(&reader, &s->palette[i].r);
				VPS_DataReader_Read8U(&reader, &s->palette[i].g);
				VPS_DataReader_Read8U(&reader, &s->palette[i].b);
			}
			IFF_ContextualData_Release(cd);
			return 1;
		}
	}

	/* CAMG */
	{
		struct IFF_Tag tag;
		IFF_Tag_Construct(&tag, (const unsigned char*)"CAMG", 4, IFF_TAG_TYPE_TAG);
		IFF_Tag_Compare(chunk_tag, &tag, &ordering);
		if (ordering == 0 && cd && cd->data && cd->data->size >= 4)
		{
			struct VPS_DataReader reader;
			VPS_DataReader_Construct(&reader, cd->data);
			VPS_DataReader_Read32UBE(&reader, &s->camg_mode);
			IFF_ContextualData_Release(cd);
			return 1;
		}
	}

	/* BODY */
	{
		struct IFF_Tag tag;
		IFF_Tag_Construct(&tag, (const unsigned char*)"BODY", 4, IFF_TAG_TYPE_TAG);
		IFF_Tag_Compare(chunk_tag, &tag, &ordering);
		if (ordering == 0 && cd && cd->data)
		{
			/* Clone BODY data — we need it for the final conversion in end_decode. */
			VPS_Data_Clone(&s->body_data, cd->data, 0, cd->data->size);
			s->has_body = 1;
			IFF_ContextualData_Release(cd);
			return 1;
		}
	}

	/* Unknown chunk — release and continue. */
	if (cd) IFF_ContextualData_Release(cd);
	return 1;
}

static char ilbm_end(struct IFF_Parser_State* state, void* custom_state, void** out_final_entity)
{
	struct ILBM_State* s = (struct ILBM_State*)custom_state;
	if (!s) return 0;

	/* Try pulling CMAP from PROP if we didn't get one in a chunk. */
	if (s->palette_size == 0)
	{
		struct IFF_Tag cmap_tag;
		struct IFF_ContextualData* prop = NULL;
		IFF_Tag_Construct(&cmap_tag, (const unsigned char*)"CMAP", 4, IFF_TAG_TYPE_TAG);
		if (IFF_Parser_State_FindProp(state, &cmap_tag, &prop) && prop && prop->data)
		{
			s->palette_size = (VPS_TYPE_16U)(prop->data->size / 3);
			if (s->palette_size > ILBM_MAX_PALETTE) s->palette_size = ILBM_MAX_PALETTE;
			struct VPS_DataReader reader;
			VPS_DataReader_Construct(&reader, prop->data);
			for (VPS_TYPE_16U i = 0; i < s->palette_size; i++)
			{
				VPS_DataReader_Read8U(&reader, &s->palette[i].r);
				VPS_DataReader_Read8U(&reader, &s->palette[i].g);
				VPS_DataReader_Read8U(&reader, &s->palette[i].b);
			}
			IFF_ContextualData_Release(prop);
		}
	}

	if (!s->has_bmhd || !s->has_body || !s->body_data)
	{
		if (s->body_data) VPS_Data_Release(s->body_data);
		free(s);
		*out_final_entity = NULL;
		return 1;
	}

	int w = s->bmhd.w;
	int h = s->bmhd.h;
	int nPlanes = s->bmhd.nPlanes;
	char is_ham = (s->camg_mode & ILBM_CAMG_HAM) != 0;
	char is_ehb = (s->camg_mode & ILBM_CAMG_EHB) != 0;

	/* Decompress BODY if ByteRun1. */
	int rb = ((w + 15) / 16) * 2;
	VPS_TYPE_SIZE decompressed_size = (VPS_TYPE_SIZE)rb * h * nPlanes;
	VPS_TYPE_8U* body_pixels = NULL;

	if (s->bmhd.compression == 1)
	{
		body_pixels = malloc(decompressed_size);
		if (!body_pixels || !ILBM_DecompressByteRun1(body_pixels, s->body_data->bytes,
		                                              s->body_data->size, decompressed_size))
		{
			free(body_pixels);
			VPS_Data_Release(s->body_data);
			free(s);
			*out_final_entity = NULL;
			return 1;
		}
	}
	else
	{
		body_pixels = s->body_data->bytes;
	}

	/* Allocate RGBA pixel buffer. */
	VPS_TYPE_SIZE pixel_bytes = (VPS_TYPE_SIZE)w * h * 4;
	VPS_TYPE_8U* pixels = malloc(pixel_bytes);
	if (!pixels)
	{
		if (s->bmhd.compression == 1) free(body_pixels);
		VPS_Data_Release(s->body_data);
		free(s);
		*out_final_entity = NULL;
		return 1;
	}
	memset(pixels, 0, pixel_bytes);

	/* Convert planar to RGBA. */
	VPS_TYPE_8U* cmap_flat = (VPS_TYPE_8U*)s->palette;
	int cmap_bytes = s->palette_size * 3;
	char success = 0;

	if (is_ham && nPlanes == 8)
		success = ILBM_ConvertHAM8ToRGBA(pixels, body_pixels, w, h, cmap_flat, cmap_bytes);
	else if (is_ham && nPlanes == 6)
		success = ILBM_ConvertHAM6ToRGBA(pixels, body_pixels, w, h, cmap_flat, cmap_bytes);
	else if (is_ehb)
		success = ILBM_ConvertEHBToRGBA(pixels, body_pixels, w, h, cmap_flat, cmap_bytes);
	else
		success = ILBM_ConvertPlanarToRGBA(pixels, body_pixels, w, h, nPlanes, cmap_flat, cmap_bytes);

	if (s->bmhd.compression == 1) free(body_pixels);
	VPS_Data_Release(s->body_data);

	if (success)
	{
		struct ILBM_Result* result = calloc(1, sizeof(struct ILBM_Result));
		if (result)
		{
			result->width = s->bmhd.w;
			result->height = s->bmhd.h;
			result->pixels = pixels;
			result->baseline = (VPS_TYPE_16U)s->bmhd.y;
		}
		else
		{
			free(pixels);
		}
		free(s);
		*out_final_entity = result;
	}
	else
	{
		free(pixels);
		free(s);
		*out_final_entity = NULL;
	}

	return 1;
}

/* ================================================================== */
/* Registration                                                       */
/* ================================================================== */

char ILBM_RegisterDecoders(struct IFF_Parser_Factory* factory)
{
	if (!factory) return 0;

	struct IFF_Tag ilbm_tag;
	IFF_Tag_Construct(&ilbm_tag, (const unsigned char*)"ILBM", 4, IFF_TAG_TYPE_TAG);

	/* Chunk decoders. */
	const char* chunk_names[] = { "BMHD", "CMAP", "BODY", "CAMG" };
	for (int i = 0; i < 4; i++)
	{
		struct IFF_Tag chunk_tag;
		IFF_Tag_Construct(&chunk_tag, (const unsigned char*)chunk_names[i], 4, IFF_TAG_TYPE_TAG);

		struct IFF_Chunk_Key* key = NULL;
		IFF_Chunk_Key_Allocate(&key);
		IFF_Chunk_Key_Construct(key, &ilbm_tag, &chunk_tag);

		struct IFF_ChunkDecoder* dec = NULL;
		if (!create_passthrough_decoder(&dec))
		{
			IFF_Chunk_Key_Release(key);
			return 0;
		}

		IFF_Parser_Factory_RegisterChunkDecoder(factory, key, dec);
	}

	/* Form decoder. */
	struct IFF_FormDecoder* form_dec = NULL;
	IFF_FormDecoder_Allocate(&form_dec);
	IFF_FormDecoder_Construct(form_dec, ilbm_begin, ilbm_process_chunk, NULL, ilbm_end);
	IFF_Parser_Factory_RegisterFormDecoder(factory, &ilbm_tag, form_dec);

	return 1;
}
