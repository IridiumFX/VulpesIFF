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
	char (*begin_encode)
	(
		struct IFF_Generator_State *state
		, void *source_entity
		, void **custom_state
	);

	/**
	 * @brief Called to produce the next chunk. Sets out_done=1 when finished.
	 */
	char (*produce_chunk)
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
	char (*produce_nested_form)
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
	char (*end_encode)
	(
		struct IFF_Generator_State *state
		, void *custom_state
	);
};

char IFF_FormEncoder_Allocate
(
	struct IFF_FormEncoder **item
);

char IFF_FormEncoder_Construct
(
	struct IFF_FormEncoder *item
	, char (*begin_encode)(struct IFF_Generator_State*, void*, void**)
	, char (*produce_chunk)(struct IFF_Generator_State*, void*, struct IFF_Tag*, struct VPS_Data**, char*)
	, char (*produce_nested_form)(struct IFF_Generator_State*, void*, struct IFF_Tag*, void**, char*)
	, char (*end_encode)(struct IFF_Generator_State*, void*)
);

char IFF_FormEncoder_Deconstruct
(
	struct IFF_FormEncoder *item
);

char IFF_FormEncoder_Release
(
	struct IFF_FormEncoder *item
);
