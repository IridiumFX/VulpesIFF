#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_ChunkDecoder.h>


char IFF_ChunkDecoder_Allocate
(
	struct IFF_ChunkDecoder **item
)
{
	if (!item)
	{
		return 0;
	}

	*item = calloc(1, sizeof(struct IFF_ChunkDecoder));

	return (char)(*item != 0);
}

char IFF_ChunkDecoder_Construct
(
	struct IFF_ChunkDecoder *item
	, char (*begin_decode)
	(
		struct IFF_Parser_State *state
		, void **custom_state
	)
	, char (*process_shard)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, const struct VPS_Data *chunk_data
	)
	, char (*end_decode)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, struct IFF_ContextualData **out
	)
)
{
	if (!item || !process_shard) // process_shard is the only mandatory function
	{
		return 0;
	}

	item->begin_decode = begin_decode;
	item->process_shard = process_shard;
	item->end_decode = end_decode;

	return 1;
}

char IFF_ChunkDecoder_Deconstruct
(
	struct IFF_ChunkDecoder *item
)
{
	if (!item)
	{
		return 0;
	}

	return 1;
}

char IFF_ChunkDecoder_Release
(
	struct IFF_ChunkDecoder *item
)
{
	if (!item)
	{
		return 0;
	}

	IFF_ChunkDecoder_Deconstruct(item);
	free(item);

	return 1;
}
