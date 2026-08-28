#pragma once

#include <IFF/IFF_Result.h>
#include <vulpes/VPS_Types.h>

struct IFF_Parser_State;
struct IFF_Tag;
struct IFF_ContextualData;

/**
 * @brief Defines the interface for a stateful FORM decoder.
 *
 * A FORM decoder is responsible for assembling a final, composite engine entity.
 * It is driven by the parser through a lifecycle of events, allowing for
 * progressive construction of the final object as its components are discovered.
 */
struct IFF_FormDecoder
{
    /**
     * @brief Called when the parser first enters the FORM container.
     */
    IFF_TYPE_RESULT (*begin_decode)(
        struct IFF_Parser_State *state,
        void **custom_state
    );

    /**
     * @brief Called for each completed data chunk found within the FORM.
     */
    IFF_TYPE_RESULT (*process_chunk)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *chunk_tag,
        struct IFF_ContextualData *contextual_data
    );

    /**
     * @brief Called for each completed, nested FORM found within this FORM.
     */
    IFF_TYPE_RESULT (*process_nested_form)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *form_type,
        void *final_entity
    );

    /**
     * @brief Called after the parser leaves the FORM container.
     */
    IFF_TYPE_RESULT (*end_decode)(
        struct IFF_Parser_State *state,
        void *custom_state,
        void **out_final_entity
    );

    /**
     * @brief Called when a child CAT or LIST container is entered.
     * @details Optional. Allows the FORM decoder to track container grouping
     *          boundaries for nested FORMs that arrive through intermediate
     *          CAT/LIST containers.
     */
    IFF_TYPE_RESULT (*enter_container)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *container_variant,
        struct IFF_Tag *container_type
    );

    /**
     * @brief Called when a child CAT or LIST container is exited.
     * @details Optional. Pairs with enter_container.
     */
    IFF_TYPE_RESULT (*leave_container)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *container_variant,
        struct IFF_Tag *container_type
    );
};

IFF_TYPE_RESULT IFF_FormDecoder_Allocate(struct IFF_FormDecoder **item);

IFF_TYPE_RESULT IFF_FormDecoder_Construct(
    struct IFF_FormDecoder *item,
    IFF_TYPE_RESULT (*begin_decode)(struct IFF_Parser_State*, void**),
    IFF_TYPE_RESULT (*process_chunk)(struct IFF_Parser_State*, void*, struct IFF_Tag*, struct IFF_ContextualData*),
    IFF_TYPE_RESULT (*process_nested_form)(struct IFF_Parser_State*, void*, struct IFF_Tag*, void*),
    IFF_TYPE_RESULT (*end_decode)(struct IFF_Parser_State*, void*, void**)
);

IFF_TYPE_RESULT IFF_FormDecoder_Deconstruct(struct IFF_FormDecoder *item);

IFF_TYPE_RESULT IFF_FormDecoder_Release(struct IFF_FormDecoder *item);

/*
 * --- VulpesCore boundary adapter ---
 *
 * The decoder/encoder registries are VulpesCore dictionaries. This shim
 * presents the typed release above through their void * slot.
 */

VPS_TYPE_RESULT IFF_FormDecoder_VPS_Release
(
	void *item
);
