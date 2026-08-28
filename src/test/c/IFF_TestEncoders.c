#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_Generator_State.h>

#include "IFF_TestEncoders.h"

// ===================================================================
// TestFormEncoder — iterates TestSourceEntity.chunks[]
// ===================================================================

struct TestFormEncoderState
{
	struct TestSourceEntity *entity;
	int chunk_index;
};

static IFF_TYPE_RESULT TestForm_BeginEncode
(
	struct IFF_Generator_State *state
	, void *source_entity
	, void **custom_state
)
{
	struct TestFormEncoderState *s = calloc(1, sizeof(struct TestFormEncoderState));
	if (!s) return IFF_FAIL;

	s->entity = (struct TestSourceEntity *)source_entity;
	s->chunk_index = 0;

	*custom_state = s;
	return IFF_OK;
}

static IFF_TYPE_RESULT TestForm_ProduceChunk
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_tag
	, struct VPS_Data **out_data
	, char *out_done
)
{
	struct TestFormEncoderState *s = custom_state;
	struct TestSourceChunk *chunk;
	struct VPS_Data *data = 0;

	if (!s) return IFF_FAIL;

	if (s->chunk_index >= s->entity->chunk_count)
	{
		*out_done = 1;
		return IFF_OK;
	}

	chunk = &s->entity->chunks[s->chunk_index];

	IFF_Tag_Construct
	(
		out_tag
		, (const unsigned char *)chunk->tag
		, 4
		, IFF_TAG_TYPE_TAG
	);

	if (VPS_Data_Allocate(&data, chunk->size, chunk->size))
	{
		return IFF_FAIL;
	}

	memcpy(data->bytes, chunk->data, chunk->size);

	*out_data = data;
	*out_done = 0;

	s->chunk_index++;

	return IFF_OK;
}

static IFF_TYPE_RESULT TestForm_ProduceNestedForm
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_form_type
	, void **out_nested_entity
	, char *out_done
)
{
	*out_done = 1;
	return IFF_OK;
}

static IFF_TYPE_RESULT TestForm_EndEncode
(
	struct IFF_Generator_State *state
	, void *custom_state
)
{
	free(custom_state);
	return IFF_OK;
}

IFF_TYPE_RESULT IFF_TestEncoders_CreateFormEncoder
(
	struct IFF_FormEncoder **out
)
{
	struct IFF_FormEncoder *enc = 0;

	if (!out) return IFF_FAIL;

	if (IFF_FormEncoder_Allocate(&enc)) return IFF_FAIL;

	if (IFF_FormEncoder_Construct
	(
		enc
		, TestForm_BeginEncode
		, TestForm_ProduceChunk
		, TestForm_ProduceNestedForm
		, TestForm_EndEncode
	))
	{
		IFF_FormEncoder_Release(enc);
		return IFF_FAIL;
	}

	*out = enc;
	return IFF_OK;
}

// ===================================================================
// TestDoublerChunkEncoder — doubles every byte
// ===================================================================

static IFF_TYPE_RESULT TestDoubler_Encode
(
	struct IFF_Generator_State *state
	, void *source_object
	, struct VPS_Data **out_data
)
{
	struct VPS_Data *src = (struct VPS_Data *)source_object;
	struct VPS_Data *result = 0;
	VPS_TYPE_SIZE i;

	if (!src || !out_data) return IFF_FAIL;

	if (VPS_Data_Allocate(&result, src->limit * 2, src->limit * 2))
	{
		return IFF_FAIL;
	}

	for (i = 0; i < src->limit; i++)
	{
		result->bytes[i * 2]     = src->bytes[i];
		result->bytes[i * 2 + 1] = src->bytes[i];
	}

	*out_data = result;
	return IFF_OK;
}

IFF_TYPE_RESULT IFF_TestEncoders_CreateDoublerChunkEncoder
(
	struct IFF_ChunkEncoder **out
)
{
	struct IFF_ChunkEncoder *enc = 0;

	if (!out) return IFF_FAIL;

	if (IFF_ChunkEncoder_Allocate(&enc)) return IFF_FAIL;

	if (IFF_ChunkEncoder_Construct(enc, TestDoubler_Encode))
	{
		IFF_ChunkEncoder_Release(enc);
		return IFF_FAIL;
	}

	*out = enc;
	return IFF_OK;
}

// ===================================================================
// EmptyFormEncoder — produce_chunk immediately sets done=1
// ===================================================================

static IFF_TYPE_RESULT EmptyForm_BeginEncode
(
	struct IFF_Generator_State *state
	, void *source_entity
	, void **custom_state
)
{
	*custom_state = 0;
	return IFF_OK;
}

static IFF_TYPE_RESULT EmptyForm_ProduceChunk
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_tag
	, struct VPS_Data **out_data
	, char *out_done
)
{
	*out_done = 1;
	return IFF_OK;
}

static IFF_TYPE_RESULT EmptyForm_EndEncode
(
	struct IFF_Generator_State *state
	, void *custom_state
)
{
	return IFF_OK;
}

IFF_TYPE_RESULT IFF_TestEncoders_CreateEmptyFormEncoder
(
	struct IFF_FormEncoder **out
)
{
	struct IFF_FormEncoder *enc = 0;

	if (!out) return IFF_FAIL;

	if (IFF_FormEncoder_Allocate(&enc)) return IFF_FAIL;

	if (IFF_FormEncoder_Construct
	(
		enc
		, EmptyForm_BeginEncode
		, EmptyForm_ProduceChunk
		, TestForm_ProduceNestedForm
		, EmptyForm_EndEncode
	))
	{
		IFF_FormEncoder_Release(enc);
		return IFF_FAIL;
	}

	*out = enc;
	return IFF_OK;
}

// ===================================================================
// FailBeginFormEncoder — begin_encode returns 0
// ===================================================================

static IFF_TYPE_RESULT FailBegin_BeginEncode
(
	struct IFF_Generator_State *state
	, void *source_entity
	, void **custom_state
)
{
	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_TestEncoders_CreateFailBeginFormEncoder
(
	struct IFF_FormEncoder **out
)
{
	struct IFF_FormEncoder *enc = 0;

	if (!out) return IFF_FAIL;

	if (IFF_FormEncoder_Allocate(&enc)) return IFF_FAIL;

	if (IFF_FormEncoder_Construct
	(
		enc
		, FailBegin_BeginEncode
		, TestForm_ProduceChunk
		, TestForm_ProduceNestedForm
		, TestForm_EndEncode
	))
	{
		IFF_FormEncoder_Release(enc);
		return IFF_FAIL;
	}

	*out = enc;
	return IFF_OK;
}

// ===================================================================
// FailSecondChunkFormEncoder — produce_chunk fails on 2nd call
// ===================================================================

static IFF_TYPE_RESULT FailSecond_ProduceChunk
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_tag
	, struct VPS_Data **out_data
	, char *out_done
)
{
	struct TestFormEncoderState *s = custom_state;

	if (!s) return IFF_FAIL;

	// First chunk succeeds normally.
	if (s->chunk_index == 0)
	{
		return TestForm_ProduceChunk(state, custom_state, out_tag, out_data, out_done);
	}

	// Second and subsequent calls fail.
	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_TestEncoders_CreateFailSecondChunkFormEncoder
(
	struct IFF_FormEncoder **out
)
{
	struct IFF_FormEncoder *enc = 0;

	if (!out) return IFF_FAIL;

	if (IFF_FormEncoder_Allocate(&enc)) return IFF_FAIL;

	if (IFF_FormEncoder_Construct
	(
		enc
		, TestForm_BeginEncode
		, FailSecond_ProduceChunk
		, TestForm_ProduceNestedForm
		, TestForm_EndEncode
	))
	{
		IFF_FormEncoder_Release(enc);
		return IFF_FAIL;
	}

	*out = enc;
	return IFF_OK;
}
