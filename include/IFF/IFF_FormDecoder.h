#pragma once

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
    char (*begin_decode)(
        struct IFF_Parser_State *state,
        void **custom_state
    );

    /**
     * @brief Called for each completed data chunk found within the FORM.
     */
    char (*process_chunk)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *chunk_tag,
        struct IFF_ContextualData *contextual_data
    );

    /**
     * @brief Called for each completed, nested FORM found within this FORM.
     */
    char (*process_nested_form)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *form_type,
        void *final_entity
    );

    /**
     * @brief Called after the parser leaves the FORM container.
     */
    char (*end_decode)(
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
    char (*enter_container)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *container_variant,
        struct IFF_Tag *container_type
    );

    /**
     * @brief Called when a child CAT or LIST container is exited.
     * @details Optional. Pairs with enter_container.
     */
    char (*leave_container)(
        struct IFF_Parser_State *state,
        void *custom_state,
        struct IFF_Tag *container_variant,
        struct IFF_Tag *container_type
    );
};

char IFF_FormDecoder_Allocate(struct IFF_FormDecoder **item);

char IFF_FormDecoder_Construct(
    struct IFF_FormDecoder *item,
    char (*begin_decode)(struct IFF_Parser_State*, void**),
    char (*process_chunk)(struct IFF_Parser_State*, void*, struct IFF_Tag*, struct IFF_ContextualData*),
    char (*process_nested_form)(struct IFF_Parser_State*, void*, struct IFF_Tag*, void*),
    char (*end_decode)(struct IFF_Parser_State*, void*, void**)
);

char IFF_FormDecoder_Deconstruct(struct IFF_FormDecoder *item);

char IFF_FormDecoder_Release(struct IFF_FormDecoder *item);
