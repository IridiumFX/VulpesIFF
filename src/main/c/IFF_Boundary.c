#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Boundary.h>

IFF_TYPE_RESULT IFF_Boundary_Allocate
(
	struct IFF_Boundary **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_Boundary));

	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Boundary_Construct
(
	struct IFF_Boundary *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->limit = 0;
	item->level = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Boundary_Deconstruct
(
	struct IFF_Boundary *item
)
{
	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Boundary_Release
(
	struct IFF_Boundary *item
)
{
	if (item)
	{
		IFF_Boundary_Deconstruct(item);
		free(item);
	}

	return IFF_OK;
}