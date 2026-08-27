#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_ChecksumCalculator.h>

IFF_TYPE_RESULT IFF_ChecksumCalculator_Allocate
(
	struct IFF_ChecksumCalculator **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_ChecksumCalculator));
	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumCalculator_Construct
(
	struct IFF_ChecksumCalculator *item,
	const struct IFF_ChecksumAlgorithm* algorithm
)
{
	IFF_TYPE_RESULT result;

	if (!item || !algorithm || !algorithm->create_context)
	{
		return IFF_FAIL;
	}

	item->algorithm = algorithm;

	// Use the algorithm's interface to create its specific context.
	result = algorithm->create_context(&item->context);
	if (result)
	{
		item->algorithm = 0;

		return result;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumCalculator_Deconstruct
(
	struct IFF_ChecksumCalculator *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	// If we have a context and a valid algorithm with a release function,
	// use the interface to release the context memory.
	if (item->algorithm && item->algorithm->release_context && item->context)
	{
		item->algorithm->release_context(item->context);
	}

	item->algorithm = 0;
	item->context = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumCalculator_Release
(
	struct IFF_ChecksumCalculator *item
)
{
	if (item)
	{
		// Deconstruct handles releasing the internal context.
		IFF_ChecksumCalculator_Deconstruct(item);
		free(item);
	}

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

char IFF_ChecksumCalculator_VPS_Release
(
	void *item
)
{
	return IFF_ChecksumCalculator_Release(item) == IFF_OK;
}
