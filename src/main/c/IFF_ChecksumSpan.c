#include <stdlib.h>

#include <vulpes/VPS_List.h>

#include <IFF/IFF_ChecksumCalculator.h>
#include <IFF/IFF_ChecksumSpan.h>

IFF_TYPE_RESULT IFF_ChecksumSpan_Allocate
(
	struct IFF_ChecksumSpan** item
)
{
	struct IFF_ChecksumSpan* span;

	if (!item)
	{
		return IFF_FAIL;
	}

	span = calloc
	(
		1
		, sizeof(struct IFF_ChecksumSpan)
	);

	if (!span)
	{
		return IFF_FAIL;
	}

	VPS_List_Allocate(&span->calculators);
	if (!span->calculators)
	{
		goto cleanup;

	}

	*item = span;

	return IFF_OK;

cleanup:

	IFF_ChecksumSpan_Release(span);

	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_ChecksumSpan_Construct
(
	struct IFF_ChecksumSpan* item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	if
	(
		VPS_List_Construct(
			item->calculators
			, 0
			, 0
			, IFF_ChecksumCalculator_VPS_Release
		)
	)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumSpan_Deconstruct
(
	struct IFF_ChecksumSpan* item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	// Deconstructing the list will clear it, which in turn calls the
	// `node_data_release` callback (IFF_ChecksumCalculator_Release) for each item.
	VPS_List_Deconstruct(item->calculators);

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ChecksumSpan_Release
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

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

VPS_TYPE_RESULT IFF_ChecksumSpan_VPS_Release
(
	void *item
)
{
	return IFF_ChecksumSpan_Release(item);
}
