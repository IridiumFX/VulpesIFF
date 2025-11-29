struct IFF_Scope
{
	union IFF_Header_Flags flags;
	struct IFF_Boundary boundary;

	// --- Container Validation Context ---
	struct IFF_Tag container_variant; // The variant of the container for this scope (FORM, LIST, CAT)
	struct IFF_Tag container_type;    // The type of the container for this scope (e.g. ILBM, or '    ' for wildcard)

	// --- Active Form Decoder State ---
	struct IFF_FormDecoder *form_decoder;
	void *form_state;
};

char IFF_Scope_Allocate
(
	struct IFF_Scope **item
);

char IFF_Scope_Construct
(
	struct IFF_Scope *item
	, union IFF_Header_Flags flags
	, struct IFF_Boundary boundary
	, struct IFF_Tag variant
	, struct IFF_Tag type
);

char IFF_Scope_Deconstruct
(
	struct IFF_Scope *item
);

char IFF_Scope_Release
(
	struct IFF_Scope *item
);
