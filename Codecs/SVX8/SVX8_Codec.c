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

#include "SVX8/SVX8_Types.h"
#include "SVX8/SVX8_Decompression.h"
#include "SVX8/SVX8_Codec.h"

/* ================================================================== */
/* Passthrough ChunkDecoder (same pattern as ILBM)                    */
/* ================================================================== */

struct PassthroughState8 { struct VPS_Data* accumulated; };

static char pt8_begin(struct IFF_Parser_State* state, void** cs)
{
	(void)state;
	*cs = calloc(1, sizeof(struct PassthroughState8));
	return (*cs != NULL);
}

static char pt8_shard(struct IFF_Parser_State* state, void* cs, const struct VPS_Data* data)
{
	(void)state;
	struct PassthroughState8* ps = cs;
	if (!ps || !data || data->size == 0) return 1;

	if (!ps->accumulated)
	{
		VPS_Data_Clone(&ps->accumulated, (struct VPS_Data*)data, 0, data->size);
	}
	else
	{
		VPS_TYPE_SIZE old = ps->accumulated->size;
		VPS_TYPE_SIZE new_sz = old + data->size;
		VPS_TYPE_8U* buf = realloc(ps->accumulated->bytes, new_sz);
		if (!buf) return 0;
		memcpy(buf + old, data->bytes, data->size);
		ps->accumulated->bytes = buf;
		ps->accumulated->size = new_sz;
		ps->accumulated->limit = new_sz;
	}
	return 1;
}

static char pt8_end(struct IFF_Parser_State* state, void* cs, struct IFF_ContextualData** out)
{
	(void)state;
	struct PassthroughState8* ps = cs;
	if (!ps || !out) return 0;

	if (ps->accumulated)
	{
		union IFF_Header_Flags flags;
		flags.as_int = 0;
		IFF_ContextualData_Allocate(out);
		IFF_ContextualData_Construct(*out, flags, ps->accumulated);
		ps->accumulated = NULL;
	}
	else *out = NULL;

	free(ps);
	return 1;
}

/* ================================================================== */
/* 8SVX FormDecoder                                                   */
/* ================================================================== */

static char svx8_begin(struct IFF_Parser_State* state, void** cs)
{
	(void)state;
	struct SVX8_State* s = calloc(1, sizeof(struct SVX8_State));
	if (!s) return 0;
	*cs = s;
	return 1;
}

static char svx8_chunk(struct IFF_Parser_State* state, void* cs, struct IFF_Tag* tag, struct IFF_ContextualData* cd)
{
	(void)state;
	struct SVX8_State* s = cs;
	if (!s) return 0;
	VPS_TYPE_16S ord;

	/* VHDR */
	{
		struct IFF_Tag vhdr_tag;
		IFF_Tag_Construct(&vhdr_tag, (const unsigned char*)"VHDR", 4, IFF_TAG_TYPE_TAG);
		IFF_Tag_Compare(tag, &vhdr_tag, &ord);
		if (ord == 0 && cd && cd->data)
		{
			struct VPS_DataReader r;
			VPS_DataReader_Construct(&r, cd->data);
			VPS_DataReader_Read32UBE(&r, &s->vhdr.oneShotHiSamples);
			VPS_DataReader_Read32UBE(&r, &s->vhdr.repeatHiSamples);
			VPS_DataReader_Read32UBE(&r, &s->vhdr.samplesPerHiCycle);
			VPS_DataReader_Read16UBE(&r, &s->vhdr.samplesPerSec);
			VPS_DataReader_Read8U(&r, &s->vhdr.ctOctave);
			VPS_DataReader_Read8U(&r, &s->vhdr.sCompression);
			VPS_DataReader_Read32SBE(&r, &s->vhdr.volume);
			s->has_vhdr = 1;
			IFF_ContextualData_Release(cd);
			return 1;
		}
	}

	/* BODY */
	{
		struct IFF_Tag body_tag;
		IFF_Tag_Construct(&body_tag, (const unsigned char*)"BODY", 4, IFF_TAG_TYPE_TAG);
		IFF_Tag_Compare(tag, &body_tag, &ord);
		if (ord == 0 && cd && cd->data)
		{
			VPS_Data_Clone(&s->body_data, cd->data, 0, cd->data->size);
			s->has_body = 1;
			IFF_ContextualData_Release(cd);
			return 1;
		}
	}

	if (cd) IFF_ContextualData_Release(cd);
	return 1;
}

static char svx8_end(struct IFF_Parser_State* state, void* cs, void** out)
{
	(void)state;
	struct SVX8_State* s = cs;
	if (!s) return 0;

	if (!s->has_vhdr || !s->has_body || !s->body_data)
	{
		if (s->body_data) VPS_Data_Release(s->body_data);
		free(s);
		*out = NULL;
		return 1;
	}

	struct SVX8_Result* result = calloc(1, sizeof(struct SVX8_Result));
	if (!result)
	{
		VPS_Data_Release(s->body_data);
		free(s);
		*out = NULL;
		return 1;
	}

	result->vhdr = s->vhdr;

	if (s->vhdr.sCompression == 1)
	{
		/* Fibonacci delta decompression. */
		VPS_TYPE_SIZE num_samples = s->vhdr.oneShotHiSamples + s->vhdr.repeatHiSamples;
		if (num_samples == 0) num_samples = s->body_data->size * 2; /* Estimate if header is zero. */

		VPS_Data_Allocate(&result->samples, num_samples, num_samples);
		if (!result->samples || !SVX8_DecompressFibonacciDelta(
			result->samples->bytes, s->body_data->bytes, s->body_data->size, num_samples))
		{
			if (result->samples) VPS_Data_Release(result->samples);
			free(result);
			VPS_Data_Release(s->body_data);
			free(s);
			*out = NULL;
			return 1;
		}
		VPS_Data_Release(s->body_data);
	}
	else
	{
		/* Uncompressed — pass through directly. */
		result->samples = s->body_data;
	}
	s->body_data = NULL;

	free(s);
	*out = result;
	return 1;
}

/* ================================================================== */
/* Registration                                                       */
/* ================================================================== */

char SVX8_RegisterDecoders(struct IFF_Parser_Factory* factory)
{
	if (!factory) return 0;

	struct IFF_Tag svx_tag;
	IFF_Tag_Construct(&svx_tag, (const unsigned char*)"8SVX", 4, IFF_TAG_TYPE_TAG);

	/* Chunk decoders. */
	const char* chunks[] = { "VHDR", "BODY" };
	for (int i = 0; i < 2; i++)
	{
		struct IFF_Tag chunk_tag;
		IFF_Tag_Construct(&chunk_tag, (const unsigned char*)chunks[i], 4, IFF_TAG_TYPE_TAG);

		struct IFF_Chunk_Key* key = NULL;
		IFF_Chunk_Key_Allocate(&key);
		IFF_Chunk_Key_Construct(key, &svx_tag, &chunk_tag);

		struct IFF_ChunkDecoder* dec = NULL;
		IFF_ChunkDecoder_Allocate(&dec);
		IFF_ChunkDecoder_Construct(dec, pt8_begin, pt8_shard, pt8_end);

		IFF_Parser_Factory_RegisterChunkDecoder(factory, key, dec);
	}

	/* Form decoder. */
	struct IFF_FormDecoder* form = NULL;
	IFF_FormDecoder_Allocate(&form);
	IFF_FormDecoder_Construct(form, svx8_begin, svx8_chunk, NULL, svx8_end);
	IFF_Parser_Factory_RegisterFormDecoder(factory, &svx_tag, form);

	return 1;
}
