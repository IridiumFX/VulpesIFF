#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_ChunkDecoder.h>


IFF_TYPE_RESULT IFF_ChunkDecoder_Allocate
(
	struct IFF_ChunkDecoder **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_ChunkDecoder));

	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChunkDecoder_Construct
(
	struct IFF_ChunkDecoder *item
	, IFF_TYPE_RESULT (*begin_decode)
	(
		struct IFF_Parser_State *state
		, void **custom_state
	)
	, IFF_TYPE_RESULT (*process_shard)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, const struct VPS_Data *chunk_data
	)
	, IFF_TYPE_RESULT (*end_decode)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, struct IFF_ContextualData **out
	)
)
{
	if (!item || !process_shard) // process_shard is the only mandatory function
	{
		return IFF_FAIL;
	}

	item->begin_decode = begin_decode;
	item->process_shard = process_shard;
	item->end_decode = end_decode;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChunkDecoder_Deconstruct
(
	struct IFF_ChunkDecoder *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChunkDecoder_Release
(
	struct IFF_ChunkDecoder *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	IFF_ChunkDecoder_Deconstruct(item);
	free(item);

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

VPS_TYPE_RESULT IFF_ChunkDecoder_VPS_Release
(
	void *item
)
{
	return IFF_ChunkDecoder_Release(item);
}
