#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk.h>

char IFF_Chunk_Allocate
(
	struct IFF_Chunk** item
)
{
	if (!item) return 0;
	*item = calloc(1, sizeof(struct IFF_Chunk));
	return *item != NULL;
}

char IFF_Chunk_Construct
(
	struct IFF_Chunk* item,
	const struct IFF_Tag* tag,
	VPS_TYPE_SIZE size,
	struct VPS_Data* data
)
{
	if (!item || !tag) return 0;

	item->tag = *tag;
	item->size = size;
	item->data = data; // The chunk takes ownership of the data.

	return 1;
}

char IFF_Chunk_Deconstruct
(
	struct IFF_Chunk* item
)
{
	if (!item) return 0;

	// Release the data payload that this chunk owns.
	VPS_Data_Release(item->data);
	item->data = NULL;

	return 1;
}

char IFF_Chunk_Release
(
	struct IFF_Chunk* item
)
{
	if (item)
	{
		IFF_Chunk_Deconstruct(item);
		free(item);
	}
	return 1;
}
