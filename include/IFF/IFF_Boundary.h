#pragma once

#include <IFF/IFF_Result.h>

struct IFF_Boundary
{
	VPS_TYPE_SIZE limit;
	VPS_TYPE_SIZE level;
};

IFF_TYPE_RESULT IFF_Boundary_Allocate
(
	struct IFF_Boundary **item
);

IFF_TYPE_RESULT IFF_Boundary_Construct
(
	struct IFF_Boundary *item
);

IFF_TYPE_RESULT IFF_Boundary_Deconstruct
(
	struct IFF_Boundary *item
);

IFF_TYPE_RESULT IFF_Boundary_Release
(
	struct IFF_Boundary *item
);
