#pragma once

#include <IFF/IFF_Result.h>
#include <vulpes/VPS_Types.h>

/**
 * @brief Per-container write state, inverse of IFF_Scope.
 * @details Tracks the configuration flags, container variant/type,
 *          and optionally an accumulator buffer for blobbed mode.
 */
struct IFF_WriteScope
{
	union IFF_Header_Flags flags;

	struct IFF_Tag container_variant;  /* FORM, LIST, CAT */
	struct IFF_Tag container_type;     /* e.g. ILBM */

	/* Blobbed mode accumulator (NULL in progressive) */
	struct VPS_Data *accumulator;
	struct VPS_DataWriter *accumulator_writer;

	/* Bytes written into this scope's content area */
	VPS_TYPE_SIZE bytes_written;

	/* Active form encoder state */
	struct IFF_FormEncoder *form_encoder;
	void *form_state;
};

IFF_TYPE_RESULT IFF_WriteScope_Allocate
(
	struct IFF_WriteScope **item
);

IFF_TYPE_RESULT IFF_WriteScope_Construct
(
	struct IFF_WriteScope *item
	, union IFF_Header_Flags flags
	, struct IFF_Tag variant
	, struct IFF_Tag type
);

IFF_TYPE_RESULT IFF_WriteScope_Deconstruct
(
	struct IFF_WriteScope *item
);

IFF_TYPE_RESULT IFF_WriteScope_Release
(
	struct IFF_WriteScope *item
);

/*
 * --- VulpesCore boundary adapter ---
 *
 * Presents the typed release above through the void * a VulpesCore
 * callback slot expects. No polarity translation: both sides agree now.
 */

VPS_TYPE_RESULT IFF_WriteScope_VPS_Release
(
	void *item
);
