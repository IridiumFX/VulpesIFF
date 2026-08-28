#pragma once

#include <IFF/IFF_Result.h>

struct VPS_Data;

/**
 * @brief Defines the interface for a stateful FORM encoder.
 * @details Inverse of IFF_FormDecoder. Driven by the generator through
 *          a lifecycle of events to produce chunks and nested FORMs
 *          from a source entity.
 */

struct IFF_Generator_State;
struct IFF_Tag;

struct IFF_FormEncoder
{
	/**
	 * @brief Called when the generator enters a FORM. Sets up encoder state.
	 */
	IFF_TYPE_RESULT (*begin_encode)
	(
		struct IFF_Generator_State *state
		, void *source_entity
		, void **custom_state
	);

	/**
	 * @brief Called to produce the next chunk. Sets out_done=1 when finished.
	 */
	IFF_TYPE_RESULT (*produce_chunk)
	(
		struct IFF_Generator_State *state
		, void *custom_state
		, struct IFF_Tag *out_tag
		, struct VPS_Data **out_data
		, char *out_done
	);

	/**
	 * @brief Called to produce nested FORMs. Sets out_done=1 when finished.
	 */
	IFF_TYPE_RESULT (*produce_nested_form)
	(
		struct IFF_Generator_State *state
		, void *custom_state
		, struct IFF_Tag *out_form_type
		, void **out_nested_entity
		, char *out_done
	);

	/**
	 * @brief Called after all chunks/forms are produced. Releases encoder state.
	 */
	IFF_TYPE_RESULT (*end_encode)
	(
		struct IFF_Generator_State *state
		, void *custom_state
	);

	/**
	 * @brief Called to produce the next container group wrapping nested FORMs.
	 * @details Optional. Called in a loop after produce_chunk and before
	 *          produce_nested_form. Each invocation opens one CAT or LIST.
	 *          Sets out_done=1 when no more container groups.
	 */
	IFF_TYPE_RESULT (*begin_container_group)
	(
		struct IFF_Generator_State *state
		, void *custom_state
		, struct IFF_Tag *out_container_variant
		, struct IFF_Tag *out_container_type
		, char *out_done
	);

	/**
	 * @brief Called to produce the next FORM inside a container group.
	 * @details Optional. Called in a loop after begin_container_group opens
	 *          a container. Sets out_done=1 when the group is complete.
	 */
	IFF_TYPE_RESULT (*produce_grouped_form)
	(
		struct IFF_Generator_State *state
		, void *custom_state
		, struct IFF_Tag *out_form_type
		, void **out_nested_entity
		, char *out_done
	);
};

IFF_TYPE_RESULT IFF_FormEncoder_Allocate
(
	struct IFF_FormEncoder **item
);

IFF_TYPE_RESULT IFF_FormEncoder_Construct
(
	struct IFF_FormEncoder *item
	, IFF_TYPE_RESULT (*begin_encode)(struct IFF_Generator_State*, void*, void**)
	, IFF_TYPE_RESULT (*produce_chunk)(struct IFF_Generator_State*, void*, struct IFF_Tag*, struct VPS_Data**, char*)
	, IFF_TYPE_RESULT (*produce_nested_form)(struct IFF_Generator_State*, void*, struct IFF_Tag*, void**, char*)
	, IFF_TYPE_RESULT (*end_encode)(struct IFF_Generator_State*, void*)
);

IFF_TYPE_RESULT IFF_FormEncoder_Deconstruct
(
	struct IFF_FormEncoder *item
);

IFF_TYPE_RESULT IFF_FormEncoder_Release
(
	struct IFF_FormEncoder *item
);

/*
 * --- VulpesCore boundary adapter ---
 *
 * The decoder/encoder registries are VulpesCore dictionaries, which expect
 * the boolean convention (1 = success). Register this shim as the release
 * hook rather than casting the function above.
 */

char IFF_FormEncoder_VPS_Release
(
	void *item
);
