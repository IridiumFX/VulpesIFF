#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_ContextualData.h>

IFF_TYPE_RESULT IFF_ContextualData_Allocate
(
	struct IFF_ContextualData **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_ContextualData));

	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ContextualData_Construct
(
	struct IFF_ContextualData *item
	, union IFF_Header_Flags flags
	, struct VPS_Data *data
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->flags = flags;
	item->data = data;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ContextualData_Deconstruct
(
	struct IFF_ContextualData *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	// The owned payload is released here (not in Release) so that a
	// Deconstruct-only user does not leak it; nulling keeps it idempotent.
	VPS_Data_Release(item->data);
	item->data = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ContextualData_Release
(
	struct IFF_ContextualData *item
)
{
	if (item)
	{
		IFF_ContextualData_Deconstruct(item);

		free(item);
	}
	return IFF_OK;
}



// --- VulpesCore boundary adapter ---

VPS_TYPE_RESULT IFF_ContextualData_VPS_Release
(
	void *item
)
{
	return IFF_ContextualData_Release(item);
}
