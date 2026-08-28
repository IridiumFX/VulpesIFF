#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Generator_State.h>
#include <IFF/IFF_ChunkEncoder.h>

IFF_TYPE_RESULT IFF_ChunkEncoder_Allocate
(
	struct IFF_ChunkEncoder **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_ChunkEncoder));

	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChunkEncoder_Construct
(
	struct IFF_ChunkEncoder *item
	, IFF_TYPE_RESULT (*encode)
	(
		struct IFF_Generator_State *state
		, void *source_object
		, struct VPS_Data **out_data
	)
)
{
	// encode is the interface's only operation: an encoder without it would
	// register fine and then be silently skipped by the generator.
	if (!item || !encode)
	{
		return IFF_FAIL;
	}

	item->encode = encode;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChunkEncoder_Deconstruct
(
	struct IFF_ChunkEncoder *item
)
{
	if (item)
	{
		item->encode = 0;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChunkEncoder_Release
(
	struct IFF_ChunkEncoder *item
)
{
	if (item)
	{
		IFF_ChunkEncoder_Deconstruct(item);
		free(item);
	}

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

VPS_TYPE_RESULT IFF_ChunkEncoder_VPS_Release
(
	void *item
)
{
	return IFF_ChunkEncoder_Release(item);
}
