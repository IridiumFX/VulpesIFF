#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_Parser_Session.h>

#include "IFF_TestDecoders.h"

// Global shard call counter for ShardCountingChunkDecoder.
int IFF_TestDecoders_ShardCallCount = 0;

// ===================================================================
// TestChunkDecoder — passthrough wrapping raw data as ContextualData
// ===================================================================

struct TestChunkState
{
	struct VPS_Data *accumulated;
};

static char TestChunk_BeginDecode
(
	struct IFF_Parser_State *state
	, void **custom_state
)
{
	struct TestChunkState *cs = calloc(1, sizeof(struct TestChunkState));
	if (!cs) return 0;

	*custom_state = cs;
	return 1;
}

static char TestChunk_ProcessShard
(
	struct IFF_Parser_State *state
	, void *custom_state
	, const struct VPS_Data *chunk_data
)
{
	struct TestChunkState *cs = custom_state;

	if (!cs) return 0;

	if (chunk_data && chunk_data->limit > 0)
	{
		if (!cs->accumulated)
		{
			VPS_Data_Clone(&cs->accumulated, (struct VPS_Data *)chunk_data, 0, chunk_data->limit);
		}
	}

	return 1;
}

static char TestChunk_EndDecode
(
	struct IFF_Parser_State *state
	, void *custom_state
	, struct IFF_ContextualData **out
)
{
	struct TestChunkState *cs = custom_state;
	struct IFF_ContextualData *cd = 0;
	union IFF_Header_Flags flags;

	if (!cs || !out) return 0;

	flags.as_int = 0;

	if (!IFF_ContextualData_Allocate(&cd))
	{
		free(cs);
		return 0;
	}

	IFF_ContextualData_Construct(cd, flags, cs->accumulated);
	cs->accumulated = 0; // ownership transferred

	*out = cd;
	free(cs);

	return 1;
}

char IFF_TestDecoders_CreateChunkDecoder
(
	struct IFF_ChunkDecoder **out_decoder
)
{
	struct IFF_ChunkDecoder *dec = 0;

	if (!out_decoder) return 0;

	if (!IFF_ChunkDecoder_Allocate(&dec)) return 0;

	if (!IFF_ChunkDecoder_Construct
	(
		dec
		, TestChunk_BeginDecode
		, TestChunk_ProcessShard
		, TestChunk_EndDecode
	))
	{
		IFF_ChunkDecoder_Release(dec);
		return 0;
	}

	*out_decoder = dec;
	return 1;
}

// ===================================================================
// ShardCountingChunkDecoder — increments global counter per shard
// ===================================================================

static char ShardCounting_ProcessShard
(
	struct IFF_Parser_State *state
	, void *custom_state
	, const struct VPS_Data *chunk_data
)
{
	IFF_TestDecoders_ShardCallCount++;

	return TestChunk_ProcessShard(state, custom_state, chunk_data);
}

char IFF_TestDecoders_CreateShardCountingChunkDecoder
(
	struct IFF_ChunkDecoder **out_decoder
)
{
	struct IFF_ChunkDecoder *dec = 0;

	if (!out_decoder) return 0;

	if (!IFF_ChunkDecoder_Allocate(&dec)) return 0;

	if (!IFF_ChunkDecoder_Construct
	(
		dec
		, TestChunk_BeginDecode
		, ShardCounting_ProcessShard
		, TestChunk_EndDecode
	))
	{
		IFF_ChunkDecoder_Release(dec);
		return 0;
	}

	*out_decoder = dec;
	return 1;
}

// ===================================================================
// TestFormDecoder — collects chunks, produces TestFormState
// ===================================================================

static char TestForm_BeginDecode
(
	struct IFF_Parser_State *state
	, void **custom_state
)
{
	struct TestFormState *fs = calloc(1, sizeof(struct TestFormState));
	if (!fs) return 0;

	fs->chunk_count = 0;
	fs->has_bmhd = 0;
	fs->prop_found = 0;
	fs->nested_form_count = 0;

	*custom_state = fs;
	return 1;
}

static char TestForm_ProcessChunk
(
	struct IFF_Parser_State *state
	, void *custom_state
	, struct IFF_Tag *chunk_tag
	, struct IFF_ContextualData *contextual_data
)
{
	struct TestFormState *fs = custom_state;
	struct IFF_Tag bmhd_tag;
	VPS_TYPE_16S ordering;

	if (!fs) return 0;

	fs->chunk_count++;

	// Check if this is a BMHD chunk with decoded data (non-null contextual_data).
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Compare(chunk_tag, &bmhd_tag, &ordering);

	if (ordering == 0 && contextual_data != 0)
	{
		fs->has_bmhd = 1;
	}

	// Release the contextual data (form decoder owns it now).
	IFF_ContextualData_Release(contextual_data);

	return 1;
}

static char TestForm_ProcessNestedForm
(
	struct IFF_Parser_State *state
	, void *custom_state
	, struct IFF_Tag *form_type
	, void *final_entity
)
{
	// No-op for test purposes.
	return 1;
}

static char TestForm_EndDecode
(
	struct IFF_Parser_State *state
	, void *custom_state
	, void **out_final_entity
)
{
	// Pass the TestFormState as the final entity.
	// Caller is responsible for freeing it.
	*out_final_entity = custom_state;
	return 1;
}

char IFF_TestDecoders_CreateFormDecoder
(
	struct IFF_FormDecoder **out_decoder
)
{
	struct IFF_FormDecoder *dec = 0;

	if (!out_decoder) return 0;

	if (!IFF_FormDecoder_Allocate(&dec)) return 0;

	if (!IFF_FormDecoder_Construct
	(
		dec
		, TestForm_BeginDecode
		, TestForm_ProcessChunk
		, TestForm_ProcessNestedForm
		, TestForm_EndDecode
	))
	{
		IFF_FormDecoder_Release(dec);
		return 0;
	}

	*out_decoder = dec;
	return 1;
}

// ===================================================================
// PropAwareFormDecoder — calls FindProp in begin_decode
// ===================================================================

static char PropAwareForm_BeginDecode
(
	struct IFF_Parser_State *state
	, void **custom_state
)
{
	struct TestFormState *fs = calloc(1, sizeof(struct TestFormState));
	struct IFF_Tag bmhd_tag;
	struct IFF_ContextualData *prop_data = 0;

	if (!fs) return 0;

	fs->chunk_count = 0;
	fs->has_bmhd = 0;
	fs->prop_found = 0;
	fs->nested_form_count = 0;

	// Attempt to pull BMHD from PROP scope.
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);

	if (IFF_Parser_State_FindProp(state, &bmhd_tag, &prop_data))
	{
		fs->prop_found = 1;
	}

	*custom_state = fs;
	return 1;
}

char IFF_TestDecoders_CreatePropAwareFormDecoder
(
	struct IFF_FormDecoder **out_decoder
)
{
	struct IFF_FormDecoder *dec = 0;

	if (!out_decoder) return 0;

	if (!IFF_FormDecoder_Allocate(&dec)) return 0;

	if (!IFF_FormDecoder_Construct
	(
		dec
		, PropAwareForm_BeginDecode
		, TestForm_ProcessChunk
		, TestForm_ProcessNestedForm
		, TestForm_EndDecode
	))
	{
		IFF_FormDecoder_Release(dec);
		return 0;
	}

	*out_decoder = dec;
	return 1;
}

// ===================================================================
// FailingFormDecoder — begin_decode returns 0
// ===================================================================

static char FailingForm_BeginDecode
(
	struct IFF_Parser_State *state
	, void **custom_state
)
{
	return 0;
}

char IFF_TestDecoders_CreateFailingFormDecoder
(
	struct IFF_FormDecoder **out_decoder
)
{
	struct IFF_FormDecoder *dec = 0;

	if (!out_decoder) return 0;

	if (!IFF_FormDecoder_Allocate(&dec)) return 0;

	if (!IFF_FormDecoder_Construct
	(
		dec
		, FailingForm_BeginDecode
		, TestForm_ProcessChunk
		, TestForm_ProcessNestedForm
		, TestForm_EndDecode
	))
	{
		IFF_FormDecoder_Release(dec);
		return 0;
	}

	*out_decoder = dec;
	return 1;
}

// ===================================================================
// NestingAwareFormDecoder — tracks nested forms
// ===================================================================

static char NestingAware_ProcessNestedForm
(
	struct IFF_Parser_State *state
	, void *custom_state
	, struct IFF_Tag *form_type
	, void *final_entity
)
{
	struct TestFormState *fs = custom_state;

	if (!fs) return 0;

	fs->nested_form_count++;

	// Free the nested entity if it was produced (TestFormState from inner FORM).
	if (final_entity)
	{
		free(final_entity);
	}

	return 1;
}

char IFF_TestDecoders_CreateNestingAwareFormDecoder
(
	struct IFF_FormDecoder **out_decoder
)
{
	struct IFF_FormDecoder *dec = 0;

	if (!out_decoder) return 0;

	if (!IFF_FormDecoder_Allocate(&dec)) return 0;

	if (!IFF_FormDecoder_Construct
	(
		dec
		, TestForm_BeginDecode
		, TestForm_ProcessChunk
		, NestingAware_ProcessNestedForm
		, TestForm_EndDecode
	))
	{
		IFF_FormDecoder_Release(dec);
		return 0;
	}

	*out_decoder = dec;
	return 1;
}
