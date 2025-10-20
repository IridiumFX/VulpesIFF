#pragma once

struct IFF_FormDecoder;

/**
 * @brief Encapsulates all state information for a single level of scope.
 *
 * This struct combines the parsing rules (flags) with the container's
 * boundary information, creating a single, coherent representation of a scope.
 */
struct IFF_Scope_State
{
	union IFF_Header_Flags flags;
	VPS_TYPE_64U boundary_size; // The total size of the container's content (0 for progressive)
	VPS_TYPE_64U bytes_scanned; // How many bytes have been scanned within this scope

    // --- Container Validation Context ---
    struct IFF_Tag container_variant; // The variant of the container for this scope (FORM, LIST, CAT)
    struct IFF_Tag container_type;    // The type of the container for this scope (e.g. ILBM, or '    ' for wildcard)

    // --- Active Form Decoder State ---
    struct IFF_FormDecoder *form_decoder;
    void *form_state;
};

char IFF_Scope_State_Allocate
(
	struct IFF_Scope_State **item
);

char IFF_Scope_State_Construct
(
	struct IFF_Scope_State *item
	, union IFF_Header_Flags flags
	, VPS_TYPE_64U boundary_size
    , struct IFF_Tag variant
    , struct IFF_Tag type
);

char IFF_Scope_State_Release
(
	struct IFF_Scope_State *item
);
