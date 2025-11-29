struct IFF_Boundary
{
	VPS_TYPE_SIZE limit;
	VPS_TYPE_SIZE level;
	VPS_TYPE_8U bounded;
};


char IFF_Boundary_Allocate
(
	struct IFF_Boundary **item
);

char IFF_Boundary_Construct
(
	struct IFF_Boundary *item,
	VPS_TYPE_8U bounded
);

char IFF_Boundary_Deconstruct
(
	struct IFF_Boundary *item
);

char IFF_Boundary_Release
(
	struct IFF_Boundary *item
);
