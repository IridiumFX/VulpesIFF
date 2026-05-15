#include <stdlib.h>

#include <vulpes/VPS_List.h>
#include <vulpes/VPS_ScopedDictionary.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Boundary.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Scope.h>
#include <IFF/IFF_Chunk_Key.h>

char IFF_Parser_Session_Allocate
(
	struct IFF_Parser_Session **item
)
{
	struct IFF_Parser_Session *state;

	if (!item)
	{
		return 0;
	}

	state = calloc(1, sizeof(struct IFF_Parser_Session));
	if (!state)
	{
		return 0;
	}

	if (!VPS_List_Allocate(&state->scope_stack))
	{
		goto failure;
	}

	if (!VPS_ScopedDictionary_Allocate(&state->props, 17))
	{
		goto failure;
	}

	*item = state;

	return 1;

failure:

	IFF_Parser_Session_Release(state);

	return 0;
}

char IFF_Parser_Session_Construct
(
	struct IFF_Parser_Session *item
	, union IFF_Header_Flags flags
)
{
	struct IFF_Boundary root_boundary;
	struct IFF_Scope* root_scope = 0;

	if (!item)
	{
		return 0;
	}

	VPS_List_Construct(item->scope_stack, 0, 0, (char (*)(void *))IFF_Scope_Release);

	// The props dictionary uses a composite IFF_Chunk_Key.
	// It takes ownership of the keys and the IFF_ContextualData values.
	VPS_ScopedDictionary_Construct
	(
		item->props,
		(char(*)(void*, VPS_TYPE_SIZE*))IFF_Chunk_Key_Hash,
		(char(*)(void*, void*, VPS_TYPE_16S*))IFF_Chunk_Key_Compare,
		0, // data_compare is not needed for this implementation.
		(char(*)(void*))IFF_Chunk_Key_Release,
		(char(*)(void*))IFF_ContextualData_Release,
		2,    // growth_multiplier
		75,   // load_percent_threshold
		8     // single_bucket_threshold
	);

	// Bootstrap the session by creating and entering the initial "root" scope.
	item->current_scope = 0;
	item->session_state = IFF_Parser_SessionState_Idle;
	item->parsing_resumed = 0;

	IFF_Scope_Allocate(&root_scope);
	IFF_Boundary_Construct(&root_boundary);
	IFF_Scope_Construct(root_scope, flags, root_boundary, IFF_TAG_SYSTEM_WILDCARD, IFF_TAG_SYSTEM_WILDCARD);

	return IFF_Parser_Session_EnterScope(item, root_scope);
}

char IFF_Parser_Session_Deconstruct
(
	struct IFF_Parser_Session *item
)
{
	if (!item)
	{
		return 0;
	}

	// Deconstruct and release the final active scope.
	IFF_Scope_Release(item->current_scope);
	item->current_scope = 0;

	// The list deconstruction will release all parent scopes on the stack.
	VPS_List_Deconstruct(item->scope_stack);
	VPS_ScopedDictionary_Deconstruct(item->props);

	return 1;
}

char IFF_Parser_Session_Release
(
	struct IFF_Parser_Session *item
)
{
	if (item)
	{
		IFF_Parser_Session_Deconstruct(item);
		VPS_List_Release(item->scope_stack);
		VPS_ScopedDictionary_Release(item->props);
		free(item);
	}

	return 1;
}

char IFF_Parser_Session_EnterScope
(
	struct IFF_Parser_Session *item,
	struct IFF_Scope* new_scope
)
{
	struct VPS_List_Node *node;

	if (!item || !new_scope) return 0;

	// 1. Compute receiving_form_scope for the new scope.
	//    If the current (parent) scope is a FORM, it becomes the receiver.
	//    Otherwise, inherit the parent's receiving_form_scope.
	if (item->current_scope)
	{
		VPS_TYPE_16S variant_ordering;
		IFF_Tag_Compare(&item->current_scope->container_variant, &IFF_TAG_SYSTEM_FORM, &variant_ordering);

		if (variant_ordering == 0)
		{
			new_scope->receiving_form_scope = item->current_scope;
		}
		else
		{
			new_scope->receiving_form_scope = item->current_scope->receiving_form_scope;
		}
	}

	// 2. If there is a current scope, push it onto the parent stack.
	if (item->current_scope)
	{
		VPS_List_Node_Allocate(&node);
		VPS_List_Node_Construct(node, item->current_scope);
		VPS_List_AddHead(item->scope_stack, node);
	}

	// 3. The new scope becomes the current active scope.
	item->current_scope = new_scope;

	// 4. Mirror the scope change in the properties dictionary.
	VPS_ScopedDictionary_EnterScope(item->props);

	return 1;
}

char IFF_Parser_Session_LeaveScope
(
	struct IFF_Parser_Session *item
)
{
	struct VPS_List_Node *parent_node = 0;

	if (!item) return 0;

	// 1. The current scope is finished, release it.
	IFF_Scope_Release(item->current_scope);
	item->current_scope = 0;

	// 2. Pop the parent scope from the stack and make it the new current scope.
	if (VPS_List_RemoveHead(item->scope_stack, &parent_node))
	{
		item->current_scope = parent_node->data;
		// The list no longer owns the node's data, so we just release the node.
		VPS_List_Node_Release(parent_node);
	}

	// 3. Mirror the scope change in the properties dictionary.
	VPS_ScopedDictionary_LeaveScope(item->props);

	return 1;
}

char IFF_Parser_Session_FindProp
(
    struct IFF_Parser_Session *item,
    struct IFF_Tag *prop_tag,
    struct IFF_ContextualData **out_prop_data
)
{
    struct IFF_Chunk_Key key;
    // The current_scope is always the correct one to search from.
    struct IFF_Scope *current_scope = item->current_scope;
    if (!current_scope) return 0;

    key.prop = *prop_tag;

    // 1. Search for a property specific to the current FORM's type.
    key.form = current_scope->container_type;
    if (VPS_ScopedDictionary_Find(item->props, &key, (void**)out_prop_data))
    {
        return 1;
    }

    // 2. Fallback to searching for a wildcard property.
    // A direct assignment is safe here because it's a by-value copy and Tags are always constructed in canonical form
    key.form = IFF_TAG_SYSTEM_WILDCARD;

    return VPS_ScopedDictionary_Find(item->props, &key, (void**)out_prop_data);
}

char IFF_Parser_Session_AddProp
(
	struct IFF_Parser_Session* item,
	struct IFF_Tag* form_type,
	struct IFF_Tag* prop_tag,
	struct IFF_ContextualData* prop_data
)
{
	struct IFF_Chunk_Key* key = 0;

	if (!item || !form_type || !prop_tag || !prop_data) return 0;

	if (!IFF_Chunk_Key_Allocate(&key)) return 0;

	// The key is a composite of the PROP's type and the property's own tag.
	key->form = *form_type;
	key->prop = *prop_tag;

	// The dictionary takes ownership of both the key and the data.
	return VPS_ScopedDictionary_Add(item->props, key, prop_data);
}

char IFF_Parser_Session_IsActive
(
	struct IFF_Parser_Session *item
)
{
	if (!item)
	{
		return 0;
	}

	if (item->session_state == IFF_Parser_SessionState_Failed
		|| item->session_state == IFF_Parser_SessionState_Complete
		|| item->session_state == IFF_Parser_SessionState_SegmentSwitch)
	{
		return 0;
	}

	return 1;
}

char IFF_Parser_Session_IsBoundaryOpen
(
	struct IFF_Parser_Session *item
)
{
	struct IFF_Boundary* boundary;

	if (!item || !item->current_scope)
	{
		return 0;
	}

	boundary = &item->current_scope->boundary;

	// A limit of 0 means unbounded (progressive mode root or initial state).
	if (boundary->limit == 0)
	{
		return 1;
	}

	return boundary->level < boundary->limit;
}

char IFF_Parser_Session_SetState
(
	struct IFF_Parser_Session *item
	, enum IFF_Parser_SessionState new_state
)
{
	if (!item)
	{
		return 0;
	}

	item->session_state = new_state;

	return 1;
}
