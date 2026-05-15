#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_ChecksumCalculator.h>

char IFF_ChecksumCalculator_Allocate
(
	struct IFF_ChecksumCalculator **item
)
{
	if (!item)
	{
		return 0;
	}

	*item = calloc(1, sizeof(struct IFF_ChecksumCalculator));

	return *item != 0;
}

char IFF_ChecksumCalculator_Construct
(
	struct IFF_ChecksumCalculator *item,
	const struct IFF_ChecksumAlgorithm* algorithm
)
{
	if (!item || !algorithm || !algorithm->create_context)
	{
		return 0;
	}

	item->algorithm = algorithm;

	// Use the algorithm's interface to create its specific context.
	if (!algorithm->create_context(&item->context))
	{
		item->algorithm = 0;
		return 0;
	}

	return 1;
}

char IFF_ChecksumCalculator_Deconstruct
(
	struct IFF_ChecksumCalculator *item
)
{
	if (!item)
	{
		return 0;
	}

	// If we have a context and a valid algorithm with a release function,
	// use the interface to release the context memory.
	if (item->algorithm && item->algorithm->release_context && item->context)
	{
		item->algorithm->release_context(item->context);
	}

	item->algorithm = 0;
	item->context = 0;

	return 1;
}

char IFF_ChecksumCalculator_Release
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

	return 1;
}