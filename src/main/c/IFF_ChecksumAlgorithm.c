#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_ChecksumAlgorithm.h>

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Allocate
(
	struct IFF_ChecksumAlgorithm **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_ChecksumAlgorithm));
	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Construct
(
	struct IFF_ChecksumAlgorithm *item
	, IFF_TYPE_RESULT (*create_context)
	(
		void** context
	)
	,void (*update)
	(
		void* context
		, const struct VPS_Data* raw_data
	)
	, IFF_TYPE_RESULT (*finalize)
	(
		void* context
		, struct VPS_Data* out_checksum
	)
	, void (*release_context)
	(
		void* context
	)
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->create_context = create_context;
	item->update = update;
	item->finalize = finalize;
	item->release_context = release_context;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Deconstruct
(
	struct IFF_ChecksumAlgorithm *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->create_context = 0;
	item->update = 0;
	item->finalize = 0;
	item->release_context = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Release
(
	struct IFF_ChecksumAlgorithm *item
)
{
	if (item)
	{
		IFF_ChecksumAlgorithm_Deconstruct(item);
		free(item);
	}

	return IFF_OK;
}
