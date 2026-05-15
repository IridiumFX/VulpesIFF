#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Boundary.h>

char IFF_Boundary_Allocate
(
	struct IFF_Boundary **item
)
{
	if (!item)
	{
		return 0;
	}

	*item = calloc(1, sizeof(struct IFF_Boundary));

	return *item != 0;
}

char IFF_Boundary_Construct
(
	struct IFF_Boundary *item
)
{
	if (!item)
	{
		return 0;
	}

	item->limit = 0;
	item->level = 0;

	return 1;
}

char IFF_Boundary_Deconstruct
(
	struct IFF_Boundary *item
)
{
	return 1;
}

char IFF_Boundary_Release
(
	struct IFF_Boundary *item
)
{
	if (item)
	{
		IFF_Boundary_Deconstruct(item);
		free(item);
	}

	return 1;
}