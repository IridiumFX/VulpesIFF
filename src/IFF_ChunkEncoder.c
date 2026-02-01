#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Generator_State.h>
#include <IFF/IFF_ChunkEncoder.h>

char IFF_ChunkEncoder_Allocate
(
	struct IFF_ChunkEncoder **item
)
{
	if (!item)
	{
		return 0;
	}

	*item = calloc(1, sizeof(struct IFF_ChunkEncoder));

	return (*item != 0);
}

char IFF_ChunkEncoder_Construct
(
	struct IFF_ChunkEncoder *item
	, char (*encode)
	(
		struct IFF_Generator_State *state
		, void *source_object
		, struct VPS_Data **out_data
	)
)
{
	if (!item)
	{
		return 0;
	}

	item->encode = encode;

	return 1;
}

char IFF_ChunkEncoder_Deconstruct
(
	struct IFF_ChunkEncoder *item
)
{
	if (item)
	{
		item->encode = 0;
	}

	return 1;
}

char IFF_ChunkEncoder_Release
(
	struct IFF_ChunkEncoder *item
)
{
	if (item)
	{
		IFF_ChunkEncoder_Deconstruct(item);
		free(item);
	}

	return 1;
}
