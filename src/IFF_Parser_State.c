#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_ScopedDictionary.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Scope_State.h>
#include <IFF/IFF_DataPump.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_Chunk_Key.h>

char IFF_Parser_State_Allocate
(
	struct IFF_Parser_State **item
)
{
	struct IFF_Parser_State *state;
	char result = 0;

	if (!item)
	{
		return 0;
	}

	state = calloc
	(
		1
		, sizeof(struct IFF_Parser_State)
	);
	if (!state)
	{
		return 0;
	}

	result = VPS_ScopedDictionary_Allocate
	(
		&state->props
		, 17
	);
	if (!result)
	{
		goto cleanup;
	}

	result = IFF_Reader_Allocate
	(
		&state->reader
	);
	if (!result)
	{
		goto cleanup;
	}

	result = VPS_List_Allocate(&state->scope_stack);
	if (!result)
	{
		goto cleanup;
	}

	*item = state;

	return 1;

cleanup:

	VPS_ScopedDictionary_Release
	(
		state->props
	);
	IFF_Reader_Release
	(
		state->reader
	);
	VPS_List_Release
	(
		state->scope_stack
	);
	free
	(
		state
	);

	return 0;
}

char IFF_Parser_State_Construct
(
	struct IFF_Parser_State *item
	, struct IFF_Parser *factory
	, int file_handle
	, union IFF_Header_Flags flags
)
{
	if (!item || !factory || file_handle < 0)
	{
		return 0;
	}

	item->final_entity = 0;

	VPS_ScopedDictionary_Construct
	(
		item->props
		, IFF_Chunk_Key_Hash
		, IFF_Chunk_Key_Compare
		, 0 // No data compare
		, (char (*)(void *)) IFF_Chunk_Key_Release // Dictionary owns the composite key
		, (char (*)(void *)) IFF_ContextualData_Release // Dictionary owns the contextual data
		, 2
		, 75
		, 8
	);

	VPS_List_Construct
	(
		item->scope_stack
		, 0
		, 0
		, (char (*)(void *)) IFF_Scope_State_Release
	);

	item->parser_factory = factory;
	item->active_header_flags = flags;

	// Create and push the root scope state onto the stack.
	struct IFF_Scope_State* root_scope = 0;
	struct VPS_List_Node* root_node = 0;
	if (!IFF_Scope_State_Allocate(&root_scope) || !VPS_List_Node_Allocate(&root_node))
	{
		IFF_Scope_State_Release(root_scope);
		VPS_List_Node_Release(root_node);
		return 0;
	}
	// The root scope is unbounded (boundary_size = 0).
	IFF_Scope_State_Construct(root_scope, flags, 0, IFF_TAG_SYSTEM_CAT, IFF_TAG_SYSTEM_CAT);
	VPS_List_Node_Construct(root_node, root_scope);
	VPS_List_AddHead(item->scope_stack, root_node);

	// Also enter the root scope for the properties dictionary.
	VPS_ScopedDictionary_EnterScope(item->props);

	return IFF_Reader_Construct
	(
		item->reader
		, file_handle
		, item
	);
}

char IFF_Parser_State_Deconstruct
(
	struct IFF_Parser_State *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_ScopedDictionary_Deconstruct
	(
		item->props
	);
	IFF_Reader_Deconstruct
	(
		item->reader
	);
	VPS_List_Deconstruct
	(
		item->scope_stack
	);

	return 1;
}

char IFF_Parser_State_Release
(
	struct IFF_Parser_State *item
)
{
	if (item)
	{
		IFF_Parser_State_Deconstruct
		(
			item
		);
		VPS_ScopedDictionary_Release
		(
			item->props
		);
		IFF_Reader_Release
		(
			item->reader
		);
		VPS_List_Release
		(
			item->scope_stack
		);
		free
		(
			item
		);
	}

	return 1;
}

char IFF_Parser_State_EnterScope
(
	struct IFF_Parser_State *state,
    struct IFF_Tag variant,
    struct IFF_Tag type
)
{
	struct IFF_Scope_State *new_scope_state = 0;
	struct VPS_List_Node *node = 0;
	char result;

	if (!state)
	{
		return 0;
	}

	result = VPS_ScopedDictionary_EnterScope
	(
		state->props
	);
	if (!result)
	{
		return 0;
	}

	if
	(
		!IFF_Scope_State_Allocate(&new_scope_state)
	)
	{
		goto cleanup;
	}

	// The new scope inherits the flags and boundary from the current scope.
	// The boundary will be updated by the Scan loop when it processes the container.
	struct IFF_Scope_State* parent_scope = state->scope_stack->head->data;
	IFF_Scope_State_Construct(new_scope_state, parent_scope->flags, parent_scope->boundary_size, variant, type);

	if
	(
		!VPS_List_Node_Allocate
		(
			&node
		)
	)
	{
		goto cleanup;
	}
	VPS_List_Node_Construct(node, new_scope_state);

	VPS_List_AddHead
	(
		state->scope_stack
		, node
	);

	return 1;

cleanup:
	VPS_ScopedDictionary_LeaveScope
	(
		state->props
	);
	IFF_Scope_State_Release(new_scope_state);
	VPS_List_Node_Release
	(
		node
	);

	return 0;
}

char IFF_Parser_State_LeaveScope
(
	struct IFF_Parser_State *state
)
{
	char result;

	if (!state || !state->scope_stack || state->scope_stack->count <= 1)
	{
		return 0;
	}

	result = VPS_ScopedDictionary_LeaveScope
	(
		state->props
	);
	if (!result)
	{
		return 0;
	}

	// Get the current (child) scope and the parent scope.
	struct IFF_Scope_State *child_scope = state->scope_stack->head->data;
	struct IFF_Scope_State *parent_scope = state->scope_stack->head->next->data;

	// Add the total bytes scanned by the child scope to the parent's counter.
	// This accounts for the entire container chunk from the parent's perspective.
	parent_scope->bytes_scanned += child_scope->bytes_scanned;

	// The list's releaser will free the IFF_Scope_State object.
	// We just need to pop the top element.
	struct VPS_List_Node *node_to_pop;
	VPS_List_RemoveHead(state->scope_stack, &node_to_pop);
	VPS_List_Node_Deconstruct(node_to_pop);
	VPS_List_Node_Release(node_to_pop);

	// The new top of the stack is the parent scope's state.
	parent_scope = state->scope_stack->head->data;

	// Update the active flags to reflect the parent scope's state.
	state->active_header_flags = parent_scope->flags;

	return 1;
}

char IFF_Parser_State_SetFlags
(
	struct IFF_Parser_State *state
	, union IFF_Header_Flags flags
)
{
	struct IFF_Scope_State *current_scope;
	if (!state || !state->scope_stack || !state->scope_stack->head)
	{
		return 0;
	}

	// Update the "hot copy" for fast access.
	state->active_header_flags = flags;

	// Also update the canonical value for the current scope at the top of the stack.
	current_scope = state->scope_stack->head->data;
	current_scope->flags = flags;

	return 1;
}

char IFF_Parser_State_DecodeContextualData(
    struct IFF_Parser_State *state,
    struct IFF_ContextualData *contextual_data,
    char (*decode_callback)(struct VPS_DataReader *reader, void *custom_state),
    void *custom_state
)
{
    if (!state || !contextual_data || !decode_callback) return 0;

    union IFF_Header_Flags original_flags = state->active_header_flags;
    char result = 0;

    // Temporarily set the parser state to match the context of the data.
    IFF_Parser_State_SetFlags(state, contextual_data->flags);

    // Create a temporary reader for the raw data.
    struct VPS_DataReader data_reader;
    VPS_DataReader_Construct(&data_reader, contextual_data->data);

    // Execute the user's decoding logic.
    result = decode_callback(&data_reader, custom_state);

    // CRITICAL: Always restore the original flags.
    IFF_Parser_State_SetFlags(state, original_flags);

    return result;
}

char IFF_Parser_State_FindProp(
    struct IFF_Parser_State *state,
    struct IFF_Tag *prop_tag,
    struct IFF_ContextualData **out_prop_data
)
{
    if (!state || !prop_tag || !out_prop_data) return 0;

    struct IFF_Scope_State *current_scope = state->scope_stack->head->data;
    struct IFF_Chunk_Key key;
    key.prop = *prop_tag;

    // 1. First, search for a type-specific property that matches the current FORM's type.
    //    Example: Look for key {'ILBM', 'CMAP'}
    key.form = current_scope->container_type;
    if (VPS_ScopedDictionary_Find(state->props, &key, (void**)out_prop_data))
    {
        return 1; // Found the most specific property.
    }

    // 2. If not found, fall back to searching for a wildcard property.
    //    Example: Look for key {'    ', 'CMAP'}
    struct IFF_Tag blank_tag;
    if (!IFF_Tag_Construct(&blank_tag, (const unsigned char*)"    ", 4, IFF_TAG_TYPE_TAG))
    {
        return 0; // Should not happen
    }
    key.form = blank_tag;
    if (VPS_ScopedDictionary_Find(state->props, &key, (void**)out_prop_data))
    {
        return 1; // Found a wildcard property.
    }

    return 0; // Property not found in any relevant scope.
}
