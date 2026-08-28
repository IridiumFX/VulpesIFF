#pragma once

#include <IFF/IFF_Result.h>

struct VPS_Data;
struct VPS_Set;

/**
 * @brief High-level imperative API for generating IFF byte streams.
 * @details Manages scope stacking, container lifecycle, directives,
 *          checksum spans, and encoder dispatch. Supports both progressive
 *          and blobbed operating modes.
 */

struct IFF_Generator_State;
struct IFF_FormEncoder;
struct IFF_ChunkEncoder;

struct IFF_Generator
{
	struct IFF_Writer *writer;
	struct VPS_List *scope_stack;
	int file_handle;

	/* Active configuration flags (updated by WriteHeader) */
	union IFF_Header_Flags flags;

	/* Blobbed mode checksum spans (LIFO stack) */
	struct VPS_List *blobbed_spans;

	/* Encoder registries (used by factory-driven path) */
	struct VPS_Dictionary *form_encoders;
	struct VPS_Dictionary *chunk_encoders;
};

IFF_TYPE_RESULT IFF_Generator_Allocate
(
	struct IFF_Generator **item
);

IFF_TYPE_RESULT IFF_Generator_Construct
(
	struct IFF_Generator *item
	, int file_handle
);

IFF_TYPE_RESULT IFF_Generator_ConstructToData
(
	struct IFF_Generator *item
);

IFF_TYPE_RESULT IFF_Generator_GetOutputData
(
	struct IFF_Generator *gen
	, struct VPS_Data **out_data
);

IFF_TYPE_RESULT IFF_Generator_Deconstruct
(
	struct IFF_Generator *item
);

IFF_TYPE_RESULT IFF_Generator_Release
(
	struct IFF_Generator *item
);

/* --- Segment-level --- */

IFF_TYPE_RESULT IFF_Generator_WriteHeader
(
	struct IFF_Generator *gen
	, const struct IFF_Header *header
);

IFF_TYPE_RESULT IFF_Generator_WriteDEF
(
	struct IFF_Generator *gen
	, const struct VPS_Data *identifier
);

IFF_TYPE_RESULT IFF_Generator_WriteREF
(
	struct IFF_Generator *gen
	, VPS_TYPE_SIZE num_options
	, const struct VPS_Data **identifiers
);

/* --- Container lifecycle --- */

IFF_TYPE_RESULT IFF_Generator_BeginForm
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
);

IFF_TYPE_RESULT IFF_Generator_EndForm
(
	struct IFF_Generator *gen
);

IFF_TYPE_RESULT IFF_Generator_BeginList
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
);

IFF_TYPE_RESULT IFF_Generator_EndList
(
	struct IFF_Generator *gen
);

IFF_TYPE_RESULT IFF_Generator_BeginCat
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
);

IFF_TYPE_RESULT IFF_Generator_EndCat
(
	struct IFF_Generator *gen
);

/* --- PROP (only valid inside LIST) --- */

IFF_TYPE_RESULT IFF_Generator_BeginProp
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
);

IFF_TYPE_RESULT IFF_Generator_EndProp
(
	struct IFF_Generator *gen
);

/* --- Chunk data --- */

IFF_TYPE_RESULT IFF_Generator_WriteChunk
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
);

/* --- Checksum spans --- */

IFF_TYPE_RESULT IFF_Generator_BeginChecksumSpan
(
	struct IFF_Generator *gen
	, const struct VPS_Set *algorithm_ids
);

IFF_TYPE_RESULT IFF_Generator_EndChecksumSpan
(
	struct IFF_Generator *gen
);

/* --- Filler and shard directives --- */

IFF_TYPE_RESULT IFF_Generator_WriteFiller
(
	struct IFF_Generator *gen
	, VPS_TYPE_SIZE size
);

IFF_TYPE_RESULT IFF_Generator_WriteShard
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
);

/* --- Version and revision directives --- */

IFF_TYPE_RESULT IFF_Generator_WriteVER
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
);

IFF_TYPE_RESULT IFF_Generator_WriteREV
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
);

/* --- Factory-driven encoding --- */

IFF_TYPE_RESULT IFF_Generator_EncodeForm
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *form_type
	, void *source_entity
);

/* --- Finalize --- */

IFF_TYPE_RESULT IFF_Generator_Flush
(
	struct IFF_Generator *gen
);
