#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk.h>

IFF_TYPE_RESULT IFF_Chunk_Allocate
(
	struct IFF_Chunk** item
)
{
	if (!item) return IFF_FAIL;
	*item = calloc(1, sizeof(struct IFF_Chunk));
	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Construct
(
	struct IFF_Chunk* item,
	const struct IFF_Tag* tag,
	VPS_TYPE_SIZE size,
	struct VPS_Data* data
)
{
	if (!item || !tag) return IFF_FAIL;

	item->tag = *tag;
	item->size = size;
	item->data = data; // The chunk takes ownership of the data.

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Deconstruct
(
	struct IFF_Chunk* item
)
{
	if (!item) return IFF_FAIL;

	// Release the data payload that this chunk owns.
	VPS_Data_Release(item->data);
	item->data = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Release
(
	struct IFF_Chunk* item
)
{
	if (item)
	{
		IFF_Chunk_Deconstruct(item);
		free(item);
	}
	return IFF_OK;
}
