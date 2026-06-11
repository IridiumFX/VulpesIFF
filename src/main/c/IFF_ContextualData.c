#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_ContextualData.h>

char IFF_ContextualData_Allocate
(
	struct IFF_ContextualData **item
)
{
	if (!item)
	{
		return 0;
	}

	*item = calloc(1, sizeof(struct IFF_ContextualData));

	return *item != 0;
}

char IFF_ContextualData_Construct
(
	struct IFF_ContextualData *item
	, union IFF_Header_Flags flags
	, struct VPS_Data *data
)
{
	if (!item)
	{
		return 0;
	}

	item->flags = flags;
	item->data = data;

	return 1;
}

char IFF_ContextualData_Deconstruct
(
	struct IFF_ContextualData *item
)
{
	if (!item)
	{
		return 0;
	}

	// The owned payload is released here (not in Release) so that a
	// Deconstruct-only user does not leak it; nulling keeps it idempotent.
	VPS_Data_Release(item->data);
	item->data = 0;

	return 1;
}

char IFF_ContextualData_Release
(
	struct IFF_ContextualData *item
)
{
	if (item)
	{
		IFF_ContextualData_Deconstruct(item);

		free(item);
	}
	return 1;
}

