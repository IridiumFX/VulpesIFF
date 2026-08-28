#pragma once

#include <IFF/IFF_Result.h>
#include <vulpes/VPS_Types.h>

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

	// --- Container Entity Routing ---
	// Points to the nearest ancestor FORM scope that can receive entities
	// produced by FORMs nested inside intermediate CAT/LIST containers.
	// NULL if no such ancestor exists (entities go to session->final_entity).
	struct IFF_Scope *receiving_form_scope;

	// --- Active Chunk Decoder State (for sharding) ---
	struct IFF_ChunkDecoder *last_chunk_decoder;
	void *last_chunk_state;
	struct IFF_Tag last_chunk_tag;
};

IFF_TYPE_RESULT IFF_Scope_Allocate
(
	struct IFF_Scope **item
);

IFF_TYPE_RESULT IFF_Scope_Construct
(
	struct IFF_Scope *item
	, union IFF_Header_Flags flags
	, struct IFF_Boundary boundary
	, struct IFF_Tag variant
	, struct IFF_Tag type
);

IFF_TYPE_RESULT IFF_Scope_Deconstruct
(
	struct IFF_Scope *item
);

IFF_TYPE_RESULT IFF_Scope_Release
(
	struct IFF_Scope *item
);

/*
 * --- VulpesCore boundary adapter ---
 *
 * Presents the typed release above through the void * a VulpesCore
 * callback slot expects. No polarity translation: both sides agree now.
 */

VPS_TYPE_RESULT IFF_Scope_VPS_Release
(
	void *item
);
