#include <stdlib.h>

#include <vulpes/VPS_List.h>

#include <IFF/IFF_ChecksumCalculator.h>
#include <IFF/IFF_ChecksumSpan.h>

char IFF_ChecksumSpan_Allocate
(
	struct IFF_ChecksumSpan** item
)
{
	struct IFF_ChecksumSpan* span;

	if (!item)
	{
		return 0;
	}

	span = calloc
	(
		1
		, sizeof(struct IFF_ChecksumSpan)
	);

	if (!span)
	{
		return 0;
	}

	VPS_List_Allocate(&span->calculators);
	if (!span->calculators)
	{
		goto cleanup;

	}

	*item = span;

	return 1;

cleanup:

	IFF_ChecksumSpan_Release(span);

	return 0;
}

char IFF_ChecksumSpan_Construct
(
	struct IFF_ChecksumSpan* item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_List_Construct
	(
		item->calculators
		, 0
		, 0
		, (char(*)(void*))IFF_ChecksumCalculator_Release
	);

	return 1;
}

char IFF_ChecksumSpan_Deconstruct
(
	struct IFF_ChecksumSpan* item
)
{
	if (!item)
	{
		return 0;
	}

	return 1;
}

char IFF_ChecksumSpan_Release
(
	struct IFF_ChecksumSpan* item
)
{
	if (item)
	{
		IFF_ChecksumSpan_Deconstruct(item);
		VPS_List_Release(item->calculators);

		free(item);
	}

	return 1;
}
