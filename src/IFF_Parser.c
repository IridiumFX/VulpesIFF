#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_DataReader.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_ScopedDictionary.h>

#include <IFF/IFF.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Chunk.h>
#include <IFF/IFF_DataPump.h>
#include <IFF/IFF_DataTap.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_Boundary.h>
#include <IFF/IFF_Scope.h>
#include <IFF/IFF_DirectiveResult.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Reader.h>
#include <IFF/IFF_ReaderFrame.h>

// Private protos
// --------------
static char PRIVATE_IFF_Parser_Parse_Container_CAT
(
	struct IFF_Parser *parser
);

static char PRIVATE_IFF_Parser_Parse_Container_LIST
(
	struct IFF_Parser *parser
);

static char PRIVATE_IFF_Parser_Parse_PROP
(
	struct IFF_Parser *parser
);

static char PRIVATE_IFF_Parser_Parse_Container_FORM
(
	struct IFF_Parser *parser
);

static char PRIVATE_IFF_Parser_Parse_Chunk
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
);

static char PRIVATE_IFF_Parser_Parse_Directive
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
	, char *out_scope_ended
);

static char PRIVATE_IFF_Parser_Parse_Container
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
);

static char PRIVATE_IFF_Parser_PushReaderAndSwitch
(
	struct IFF_Parser *parser
	, int new_file_handle
);

static char PRIVATE_IFF_Parser_PopReaderAndRestore
(
	struct IFF_Parser *parser
);

static char PRIVATE_IFF_Parser_HandleSegmentRef
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
);


// --- Lifecycle ---

char IFF_Parser_Allocate
(
	struct IFF_Parser **item
)
{
	struct IFF_Parser *parser;

	if (!item)
	{
		return 0;
	}

	parser = calloc
	(
		1,
		sizeof(struct IFF_Parser)
	);
	if (!parser)
	{
		*item = 0;

		return 0;
	}

	IFF_Parser_Session_Allocate
	(
		&parser->session
	);
	if (!parser->session)
	{
		goto cleanup;
	}

	IFF_Reader_Allocate
	(
		&parser->reader
	);
	if (!parser->reader)
	{
		goto cleanup;
	}

	VPS_List_Allocate
	(
		&parser->reader_stack
	);
	if (!parser->reader_stack)
	{
		goto cleanup;
	}

	*item = parser;

	return 1;

cleanup:

	*item = 0;

	IFF_Parser_Release
	(
		parser
	);

	return 0;
}

char IFF_Parser_Construct
(
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, int file_handle
)
{
	char result;

	if (!item || !form_decoders || !chunk_decoders || !directive_processors || !item->session)
	{
		return 0;
	}

	item->form_decoders = form_decoders;
	item->chunk_decoders = chunk_decoders;
	item->directive_processors = directive_processors;
	item->file_handle = file_handle;

	result = IFF_Parser_Session_Construct
	(
		item->session,
		IFF_HEADER_FLAGS_1985
	);
	if (!result)
	{
		return 0;
	}

	result = IFF_Reader_Construct
	(
		item->reader,
		file_handle
	);
	if (!result)
	{
		return 0;
	}

	VPS_List_Construct
	(
		item->reader_stack,
		0,
		0,
		(char(*)(void*))IFF_ReaderFrame_Release
	);

	item->segment_resolver = 0;
	item->resolver_context = 0;
	item->strict_references = 0;

	return 1;
}

char IFF_Parser_ConstructFromData
(
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, const struct VPS_Data *source
)
{
	if (!item || !form_decoders || !chunk_decoders || !directive_processors || !item->session)
	{
		return 0;
	}

	item->form_decoders = form_decoders;
	item->chunk_decoders = chunk_decoders;
	item->directive_processors = directive_processors;
	item->file_handle = -1;

	if
	(
		!IFF_Parser_Session_Construct
		(
			item->session,
			IFF_HEADER_FLAGS_1985
		)
	)
	{
		return 0;
	}

	if
	(
		!IFF_Reader_ConstructFromData
		(
			item->reader,
			source
		)
	)
	{
		return 0;
	}

	VPS_List_Construct
	(
		item->reader_stack,
		0,
		0,
		(char(*)(void*))IFF_ReaderFrame_Release
	);

	item->segment_resolver = 0;
	item->resolver_context = 0;
	item->strict_references = 0;

	return 1;
}

char IFF_Parser_Deconstruct
(
	struct IFF_Parser *item
)
{
	if (!item)
	{
		return 0;
	}

	// Unwind the reader stack: pop all saved frames and restore the original
	// reader so that only the root reader is deconstructed below.
	if (item->reader_stack)
	{
		while (item->reader_stack->count > 0)
		{
			struct VPS_List_Node *node = 0;

			if (VPS_List_RemoveHead(item->reader_stack, &node))
			{
				struct IFF_ReaderFrame *frame = node->data;

				// Release the current (included) reader.
				IFF_Reader_Release(item->reader);
				close(item->file_handle);

				// Restore the parent reader from the frame.
				item->reader = frame->reader;
				item->file_handle = frame->file_handle;

				// Prevent double-free: frame no longer owns these.
				frame->reader = 0;
				frame->file_handle = -1;

				IFF_ReaderFrame_Release(frame);
				VPS_List_Node_Release(node);
			}
		}

		VPS_List_Deconstruct(item->reader_stack);
	}

	IFF_Parser_Session_Deconstruct
	(
		item->session
	);

	IFF_Reader_Deconstruct
	(
		item->reader
	);

	// NOTE: This is platform specific. Need a better abstraction
	item->file_handle = -1;

	return 1;
}

char IFF_Parser_Release
(
	struct IFF_Parser *item
)
{
	if (!item)
	{
		return 0;
	}

	IFF_Parser_Deconstruct
	(
		item
	);

	IFF_Parser_Session_Release
	(
		item->session
	);

	IFF_Reader_Release
	(
		item->reader
	);

	VPS_List_Release
	(
		item->reader_stack
	);

	free
	(
		item
	);

	return 1;
}


// --- Shard Flush ---

/**
 * @brief Finalizes any pending chunk decoder stored in the current scope.
 *
 * When SHARDING is enabled, end_decode is deferred until the next non-shard
 * event (new chunk, nested container, scope exit). This helper performs
 * that deferred finalization and routes the result through the same
 * PROP-vs-FORM logic as Parse_Chunk.
 */
static char PRIVATE_IFF_Parser_FlushLastDecoder
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session* session = parser->session;
	struct IFF_Scope* scope = session->current_scope;
	struct IFF_ContextualData* contextual_data = 0;
	struct IFF_Parser_State parser_state;
	VPS_TYPE_16S variant_ordering;

	if (!scope->last_chunk_decoder)
	{
		return 1;
	}

	parser_state.session = session;

	// Finalize the pending decoder.
	if (scope->last_chunk_decoder->end_decode)
	{
		if (!scope->last_chunk_decoder->end_decode
		(
			&parser_state,
			scope->last_chunk_state,
			&contextual_data
		))
		{
			scope->last_chunk_decoder = 0;
			scope->last_chunk_state = 0;
			return 0;
		}
	}

	// Route the result.
	IFF_Tag_Compare(&scope->container_variant, &IFF_TAG_SYSTEM_PROP, &variant_ordering);

	if (variant_ordering == 0)
	{
		if (contextual_data)
		{
			IFF_Parser_Session_AddProp
			(
				session,
				&scope->container_type,
				&scope->last_chunk_tag,
				contextual_data
			);
			contextual_data = 0;
		}
	}
	else if (scope->form_decoder && scope->form_decoder->process_chunk && contextual_data)
	{
		char result = scope->form_decoder->process_chunk
		(
			&parser_state,
			scope->form_state,
			&scope->last_chunk_tag,
			contextual_data
		);
		contextual_data = 0;

		if (!result)
		{
			scope->last_chunk_decoder = 0;
			scope->last_chunk_state = 0;
			return 0;
		}
	}
	else if (contextual_data)
	{
		IFF_ContextualData_Release(contextual_data);
		contextual_data = 0;
	}

	scope->last_chunk_decoder = 0;
	scope->last_chunk_state = 0;

	return 1;
}


// --- Directive Handling ---

char IFF_Parser_ExecuteDirective
(
	struct IFF_Parser *parser,
	struct IFF_Chunk *directive_chunk
)
{
	char result;

	if (!parser || !directive_chunk)
	{
		return 0;
	}

	// Find the registered processor for this directive tag.
	char (*processor)
	(
		const struct IFF_Chunk *chunk,
		struct IFF_DirectiveResult *result
	) = 0;

	result = VPS_Dictionary_Find
	(
		parser->directive_processors,
		&directive_chunk->tag,
		(void**)&processor
	);
	if (result)
	{
		struct IFF_DirectiveResult directive_result;

		result = processor(directive_chunk, &directive_result);
		if (result)
		{
			switch (directive_result.action)
			{
				case IFF_ACTION_UPDATE_FLAGS:
				{
					// Scope guards: validate that the new flags do not exceed
					// the parent scope's constraints.
					struct VPS_List_Node* head_node = parser->session->scope_stack->head;

					if (head_node && head_node->next)
					{
						struct IFF_Scope* parent_scope = head_node->next->data;
						union IFF_Header_Flags new_flags = directive_result.payload.new_flags;
						union IFF_Header_Flags parent_flags = parent_scope->flags;

						// Guard 1: Size widening — child cannot use wider sizes
						// than the parent's boundary can represent.
						if (IFF_Header_Flags_GetSizeLength(new_flags.as_fields.sizing)
							> IFF_Header_Flags_GetSizeLength(parent_flags.as_fields.sizing))
						{
							return 0;
						}

						// Guard 2: Blobbed-to-progressive — progressive mode
						// requires ' END' which falls outside a blobbed parent's
						// declared boundary.
						if (parent_flags.as_fields.operating == IFF_Header_Operating_BLOBBED
							&& new_flags.as_fields.operating == IFF_Header_Operating_PROGRESSIVE)
						{
							return 0;
						}

						// Guard 3: Tag widening — wider tags would misalign the
						// parent's boundary tracking.
						if (IFF_Header_Flags_GetTagLength(new_flags.as_fields.tag_sizing)
							> IFF_Header_Flags_GetTagLength(parent_flags.as_fields.tag_sizing))
						{
							return 0;
						}
					}

					parser->session->current_scope->flags = directive_result.payload.new_flags;
				}
				break;

				case IFF_ACTION_LOCK_IFF85:
				{
					parser->session->iff85_locked = 1;
					parser->session->current_scope->flags.as_int = 0;
				}
				break;

				case IFF_ACTION_HALT:
				{
					return 0;
				}
				break;

				default:
				{
				}
				break;
			}
		}
	}

	return 1;
}

/**
 * @brief Reads a directive chunk (size + data), updates the boundary, handles
 *        padding, and passes to ExecuteDirective for registered processors.
 */
static char PRIVATE_IFF_Parser_ReadAndExecuteDirective
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
)
{
	struct IFF_Scope* scope = parser->session->current_scope;
	union IFF_Header_Flags flags = scope->flags;
	struct IFF_Chunk* chunk = 0;
	char result;

	result = IFF_Reader_ReadChunk
	(
		parser->reader,
		&flags.as_fields,
		&tag,
		&chunk
	);
	if (!result)
	{
		return 0;
	}

	// Track boundary: size field + data payload
	scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
		+ chunk->size;

	// Handle padding for odd-length directive data
	if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
		&& (chunk->size & 1))
	{
		IFF_Reader_Skip(parser->reader, 1);
		scope->boundary.level += 1;
	}

	result = IFF_Parser_ExecuteDirective(parser, chunk);
	IFF_Chunk_Release(chunk);

	return result;
}

/**
 * @brief Routes a directive tag to the appropriate handler.
 * @param out_scope_ended Set to 1 if ' END' was encountered. May be NULL.
 */
static char PRIVATE_IFF_Parser_Parse_Directive
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
	, char *out_scope_ended
)
{
	struct IFF_Scope* scope;
	union IFF_Header_Flags flags;
	VPS_TYPE_16S ordering;
	VPS_TYPE_SIZE end_size;
	char result;

	scope = parser->session->current_scope;
	flags = scope->flags;

	if (out_scope_ended)
	{
		*out_scope_ended = 0;
	}

	// --- IFF-85 lock: reject all directives except filler ('    ') ---
	if (parser->session->iff85_locked)
	{
		IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_SHARD, &ordering);

		if (ordering == 0)
		{
			// Filler: read and skip via generic handler.
			return PRIVATE_IFF_Parser_ReadAndExecuteDirective(parser, tag);
		}

		// All other directives are invalid in IFF-85 mode.
		return 0;
	}

	// --- ' END' ---
	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_END, &ordering);
	if (ordering == 0)
	{
		// Read the size field (must be 0).
		result = IFF_Reader_ReadSize
		(
			parser->reader,
			flags.as_fields.sizing,
			flags.as_fields.typing,
			&end_size
		);
		if (!result || end_size != 0)
		{
			return 0;
		}

		scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing);

		if (out_scope_ended)
		{
			*out_scope_ended = 1;
		}

		return 1;
	}

	// --- ' CHK' (start checksum span) ---
	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_CHK, &ordering);
	if (ordering == 0)
	{
		struct IFF_Chunk* chunk = 0;

		result = IFF_Reader_ReadChunk
		(
			parser->reader,
			&flags.as_fields,
			&tag,
			&chunk
		);
		if (!result)
		{
			return 0;
		}

		scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
			+ chunk->size;

		if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
			&& (chunk->size & 1))
		{
			IFF_Reader_Skip(parser->reader, 1);
			scope->boundary.level += 1;
		}

		result = IFF_Reader_StartChecksumSpan
		(
			parser->reader,
			&flags.as_fields,
			chunk->data
		);

		IFF_Chunk_Release(chunk);

		return result;
	}

	// --- ' SUM' (end checksum span and verify) ---
	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_SUM, &ordering);
	if (ordering == 0)
	{
		struct IFF_Chunk* chunk = 0;
		struct VPS_List_Node* paused_span_node = 0;

		// Pause the active checksum span. The SUM tag was already read by
		// the content loop's ReadTag (through the DataTap), so those bytes
		// are included in the checksum. However, the SUM size and data
		// must NOT be checksummed. Temporarily remove the span so that
		// ReadChunk's reads bypass checksum accumulation.
		if (parser->reader->tap->active_spans->count > 0)
		{
			VPS_List_RemoveHead(parser->reader->tap->active_spans, &paused_span_node);
		}

		result = IFF_Reader_ReadChunk
		(
			parser->reader,
			&flags.as_fields,
			&tag,
			&chunk
		);
		if (!result)
		{
			// Restore span before returning so cleanup can release it.
			if (paused_span_node)
			{
				VPS_List_AddHead(parser->reader->tap->active_spans, paused_span_node);
			}
			return 0;
		}

		scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
			+ chunk->size;

		// Handle padding for the SUM directive (still unchecksummed).
		if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
			&& (chunk->size & 1))
		{
			IFF_Reader_Skip(parser->reader, 1);
			scope->boundary.level += 1;
		}

		// Restore the span so EndSpan can pop and finalize it.
		if (paused_span_node)
		{
			VPS_List_AddHead(parser->reader->tap->active_spans, paused_span_node);
		}

		result = IFF_Reader_EndChecksumSpan
		(
			parser->reader,
			&flags.as_fields,
			chunk->data
		);

		IFF_Chunk_Release(chunk);

		return result;
	}

	// --- '    ' (shard or filler) ---
	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_SHARD, &ordering);
	if (ordering == 0)
	{
		if (flags.as_fields.structuring & IFF_Header_Flag_Structuring_SHARDING)
		{
			// Shard mode: read the chunk and pass data to the pending decoder.
			struct IFF_Chunk* chunk = 0;

			result = IFF_Reader_ReadChunk
			(
				parser->reader,
				&flags.as_fields,
				&tag,
				&chunk
			);
			if (!result)
			{
				return 0;
			}

			scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
				+ chunk->size;

			if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
				&& (chunk->size & 1))
			{
				IFF_Reader_Skip(parser->reader, 1);
				scope->boundary.level += 1;
			}

			// Dispatch to the pending chunk decoder, if any.
			if (scope->last_chunk_decoder && scope->last_chunk_decoder->process_shard)
			{
				struct IFF_Parser_State parser_state;
				parser_state.session = parser->session;

				result = scope->last_chunk_decoder->process_shard
				(
					&parser_state,
					scope->last_chunk_state,
					chunk->data
				);

				IFF_Chunk_Release(chunk);

				return result;
			}

			// No active decoder — silently consume as filler.
			IFF_Chunk_Release(chunk);

			return 1;
		}

		// Filler mode (SHARDING not set): read and skip.
		return PRIVATE_IFF_Parser_ReadAndExecuteDirective(parser, tag);
	}

	// --- ' DEF' (segment identity declaration) ---
	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_DEF, &ordering);
	if (ordering == 0)
	{
		return PRIVATE_IFF_Parser_ReadAndExecuteDirective(parser, tag);
	}

	// --- ' IFF' ---
	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_IFF, &ordering);
	if (ordering == 0)
	{
		return PRIVATE_IFF_Parser_ReadAndExecuteDirective(parser, tag);
	}

	// --- All other directives (' VER', ' REV', ' REF', unknown) ---
	// Read and skip. The generic handler in ExecuteDirective will invoke a
	// registered processor if one exists; otherwise the data is just consumed.
	return PRIVATE_IFF_Parser_ReadAndExecuteDirective(parser, tag);
}


// --- Container Dispatcher ---

static char PRIVATE_IFF_Parser_Parse_Container
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
)
{
	VPS_TYPE_16S ordering;

	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_FORM, &ordering);
	if (ordering == 0)
	{
		return PRIVATE_IFF_Parser_Parse_Container_FORM(parser);
	}

	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_LIST, &ordering);
	if (ordering == 0)
	{
		return PRIVATE_IFF_Parser_Parse_Container_LIST(parser);
	}

	IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_CAT, &ordering);
	if (ordering == 0)
	{
		return PRIVATE_IFF_Parser_Parse_Container_CAT(parser);
	}

	return 0;
}


// --- FORM Container ---

static char PRIVATE_IFF_Parser_Parse_Container_FORM
(
	struct IFF_Parser *parser
)
{
	struct IFF_Scope* parent_scope = parser->session->current_scope;
	union IFF_Header_Flags parent_flags = parent_scope->flags;
	VPS_TYPE_SIZE container_size = 0;
	VPS_TYPE_8U tag_size = IFF_Header_Flags_GetTagLength(parent_flags.as_fields.tag_sizing);
	VPS_TYPE_8U size_len = IFF_Header_Flags_GetSizeLength(parent_flags.as_fields.sizing);
	struct IFF_Tag form_type;
	struct IFF_Tag tag;
	struct IFF_Scope* child_scope = 0;
	struct IFF_Boundary child_boundary;
	struct IFF_FormDecoder* decoder = 0;
	struct IFF_Parser_State parser_state;
	void* final_entity = 0;
	char result;

	// 1. If blobbed mode, read container size and update parent boundary.
	if (parent_flags.as_fields.operating == IFF_Header_Operating_BLOBBED)
	{
		result = IFF_Reader_ReadSize
		(
			parser->reader,
			parent_flags.as_fields.sizing,
			parent_flags.as_fields.typing,
			&container_size
		);
		if (!result)
		{
			return 0;
		}

		parent_scope->boundary.level += size_len + container_size;
	}

	// 2. Read the FORM's type tag.
	result = IFF_Reader_ReadTag
	(
		parser->reader,
		parent_flags.as_fields.tag_sizing,
		&form_type
	);
	if (!result)
	{
		return 0;
	}

	// Type tags are content identifiers, not structural markers.
	// ReadTag may misclassify all-space types as DIRECTIVE; force to TAG.
	form_type.type = IFF_TAG_TYPE_TAG;

	// Validate: FORM type must not be blank.
	{
		VPS_TYPE_16S type_ordering;
		IFF_Tag_Compare(&form_type, &IFF_TAG_SYSTEM_WILDCARD, &type_ordering);
		if (type_ordering == 0)
		{
			return 0;
		}
	}

	// Strict container validation: if parent is CAT or LIST with a non-wildcard
	// type and STRICT_CONTAINERS is set, the FORM type must match.
	if (parent_flags.as_fields.structuring & IFF_Header_Flag_Structuring_STRICT_CONTAINERS)
	{
		VPS_TYPE_16S variant_ordering;
		VPS_TYPE_16S wildcard_ordering;
		char parent_is_aggregator = 0;

		IFF_Tag_Compare(&parent_scope->container_variant, &IFF_TAG_SYSTEM_CAT, &variant_ordering);
		if (variant_ordering == 0)
		{
			parent_is_aggregator = 1;
		}

		if (!parent_is_aggregator)
		{
			IFF_Tag_Compare(&parent_scope->container_variant, &IFF_TAG_SYSTEM_LIST, &variant_ordering);
			if (variant_ordering == 0)
			{
				parent_is_aggregator = 1;
			}
		}

		if (parent_is_aggregator)
		{
			IFF_Tag_Compare(&parent_scope->container_type, &IFF_TAG_SYSTEM_WILDCARD, &wildcard_ordering);
			if (wildcard_ordering != 0)
			{
				VPS_TYPE_16S type_match;
				IFF_Tag_Compare(&form_type, &parent_scope->container_type, &type_match);
				if (type_match != 0)
				{
					return 0;
				}
			}
		}
	}

	// 3. Create and enter a child scope.
	IFF_Boundary_Construct(&child_boundary);
	child_boundary.limit = container_size;
	child_boundary.level = tag_size; // Type tag already consumed.

	if (!IFF_Scope_Allocate(&child_scope))
	{
		return 0;
	}

	IFF_Scope_Construct
	(
		child_scope,
		parent_flags,
		child_boundary,
		IFF_TAG_SYSTEM_FORM,
		form_type
	);

	IFF_Parser_Session_EnterScope(parser->session, child_scope);

	// 4. Look up and start the form decoder.
	parser_state.session = parser->session;

	if (VPS_Dictionary_Find(parser->form_decoders, &form_type, (void**)&decoder))
	{
		child_scope->form_decoder = decoder;

		if (decoder->begin_decode)
		{
			if (!decoder->begin_decode(&parser_state, &child_scope->form_state))
			{
				IFF_Parser_Session_LeaveScope(parser->session);
				return 0;
			}
		}
	}

	// 5. Content loop.
	while (IFF_Parser_Session_IsActive(parser->session)
		&& IFF_Parser_Session_IsBoundaryOpen(parser->session))
	{
		result = IFF_Reader_ReadTag
		(
			parser->reader,
			parser->session->current_scope->flags.as_fields.tag_sizing,
			&tag
		);
		if (!result)
		{
			break;
		}

		parser->session->current_scope->boundary.level +=
			IFF_Header_Flags_GetTagLength(parser->session->current_scope->flags.as_fields.tag_sizing);

		switch (tag.type)
		{
			case IFF_TAG_TYPE_DIRECTIVE:
			{
				char scope_ended = 0;

				result = PRIVATE_IFF_Parser_Parse_Directive
				(
					parser,
					tag,
					&scope_ended
				);
				if (!result)
				{
					goto form_cleanup;
				}
				if (scope_ended)
				{
					goto form_done;
				}
			}
			break;

			case IFF_TAG_TYPE_CONTAINER:
			{
				// Flush any pending shard decoder before nested container.
				if (!PRIVATE_IFF_Parser_FlushLastDecoder(parser))
				{
					goto form_cleanup;
				}

				result = PRIVATE_IFF_Parser_Parse_Container
				(
					parser,
					tag
				);
				if (!result)
				{
					goto form_cleanup;
				}
			}
			break;

			case IFF_TAG_TYPE_TAG:
			{
				result = PRIVATE_IFF_Parser_Parse_Chunk
				(
					parser,
					tag
				);
				if (!result)
				{
					goto form_cleanup;
				}
			}
			break;

			// PROP not allowed inside FORM.
			default:
			{
				goto form_cleanup;
			}
		}
	}

form_done:

	// Flush any pending shard decoder before ending the form.
	PRIVATE_IFF_Parser_FlushLastDecoder(parser);

	// 6. End the form decoder.
	if (child_scope->form_decoder && child_scope->form_decoder->end_decode)
	{
		parser_state.session = parser->session;

		child_scope->form_decoder->end_decode
		(
			&parser_state,
			child_scope->form_state,
			&final_entity
		);
	}

	// 7. Leave scope — parent is restored.
	IFF_Parser_Session_LeaveScope(parser->session);

	// 8. Pass the result to the parent's form decoder, or store as session result.
	if (final_entity)
	{
		struct IFF_Scope* restored_parent = parser->session->current_scope;

		if (restored_parent
			&& restored_parent->form_decoder
			&& restored_parent->form_decoder->process_nested_form)
		{
			parser_state.session = parser->session;

			restored_parent->form_decoder->process_nested_form
			(
				&parser_state,
				restored_parent->form_state,
				&form_type,
				final_entity
			);
		}
		else
		{
			parser->session->final_entity = final_entity;
		}
	}

	return 1;

form_cleanup:

	// Flush any pending shard decoder before cleanup.
	PRIVATE_IFF_Parser_FlushLastDecoder(parser);

	// End the decoder on failure (if it was started).
	if (child_scope->form_decoder && child_scope->form_decoder->end_decode)
	{
		parser_state.session = parser->session;
		child_scope->form_decoder->end_decode(&parser_state, child_scope->form_state, &final_entity);
	}

	IFF_Parser_Session_LeaveScope(parser->session);

	return 0;
}


// --- PROP Container ---

static char PRIVATE_IFF_Parser_Parse_PROP
(
	struct IFF_Parser *parser
)
{
	struct IFF_Scope* parent_scope = parser->session->current_scope;
	union IFF_Header_Flags parent_flags = parent_scope->flags;
	VPS_TYPE_SIZE container_size = 0;
	VPS_TYPE_8U tag_size = IFF_Header_Flags_GetTagLength(parent_flags.as_fields.tag_sizing);
	VPS_TYPE_8U size_len = IFF_Header_Flags_GetSizeLength(parent_flags.as_fields.sizing);
	struct IFF_Tag prop_type;
	struct IFF_Tag tag;
	struct IFF_Scope* child_scope = 0;
	struct IFF_Boundary child_boundary;
	char result;

	// 1. If blobbed mode, read container size and update parent boundary.
	if (parent_flags.as_fields.operating == IFF_Header_Operating_BLOBBED)
	{
		result = IFF_Reader_ReadSize
		(
			parser->reader,
			parent_flags.as_fields.sizing,
			parent_flags.as_fields.typing,
			&container_size
		);
		if (!result)
		{
			return 0;
		}

		parent_scope->boundary.level += size_len + container_size;
	}

	// 2. Read PROP type tag.
	result = IFF_Reader_ReadTag
	(
		parser->reader,
		parent_flags.as_fields.tag_sizing,
		&prop_type
	);
	if (!result)
	{
		return 0;
	}

	// Type tags are content identifiers; force classification to TAG.
	prop_type.type = IFF_TAG_TYPE_TAG;

	// 3. Create and enter child scope.
	IFF_Boundary_Construct(&child_boundary);
	child_boundary.limit = container_size;
	child_boundary.level = tag_size;

	if (!IFF_Scope_Allocate(&child_scope))
	{
		return 0;
	}

	IFF_Scope_Construct
	(
		child_scope,
		parent_flags,
		child_boundary,
		IFF_TAG_SYSTEM_PROP,
		prop_type
	);

	IFF_Parser_Session_EnterScope(parser->session, child_scope);

	// PROP entries must persist at the parent (LIST) scope so sibling FORMs
	// can retrieve them via FindProp. Undo the ScopedDictionary scope push
	// that EnterScope performed; entries will land in the LIST's scope.
	VPS_ScopedDictionary_LeaveScope(parser->session->props);

	// 4. Content loop — only data chunks and directives allowed.
	while (IFF_Parser_Session_IsActive(parser->session)
		&& IFF_Parser_Session_IsBoundaryOpen(parser->session))
	{
		result = IFF_Reader_ReadTag
		(
			parser->reader,
			parser->session->current_scope->flags.as_fields.tag_sizing,
			&tag
		);
		if (!result)
		{
			break;
		}

		parser->session->current_scope->boundary.level +=
			IFF_Header_Flags_GetTagLength(parser->session->current_scope->flags.as_fields.tag_sizing);

		switch (tag.type)
		{
			case IFF_TAG_TYPE_DIRECTIVE:
			{
				char scope_ended = 0;

				result = PRIVATE_IFF_Parser_Parse_Directive
				(
					parser,
					tag,
					&scope_ended
				);
				if (!result)
				{
					PRIVATE_IFF_Parser_FlushLastDecoder(parser);
					VPS_ScopedDictionary_EnterScope(parser->session->props);
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
				if (scope_ended)
				{
					goto prop_done;
				}
			}
			break;

			case IFF_TAG_TYPE_TAG:
			{
				result = PRIVATE_IFF_Parser_Parse_Chunk
				(
					parser,
					tag
				);
				if (!result)
				{
					PRIVATE_IFF_Parser_FlushLastDecoder(parser);
					VPS_ScopedDictionary_EnterScope(parser->session->props);
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
			}
			break;

			// No container nesting allowed in PROP.
			default:
			{
				PRIVATE_IFF_Parser_FlushLastDecoder(parser);
				VPS_ScopedDictionary_EnterScope(parser->session->props);
				IFF_Parser_Session_LeaveScope(parser->session);
				return 0;
			}
		}
	}

prop_done:

	// Flush any pending shard decoder before leaving PROP scope.
	PRIVATE_IFF_Parser_FlushLastDecoder(parser);

	// Re-enter the ScopedDictionary scope so LeaveScope can leave it.
	// This balances the LeaveScope we did after EnterScope above.
	VPS_ScopedDictionary_EnterScope(parser->session->props);
	IFF_Parser_Session_LeaveScope(parser->session);

	return 1;
}


// --- LIST Container ---

static char PRIVATE_IFF_Parser_Parse_Container_LIST
(
	struct IFF_Parser *parser
)
{
	struct IFF_Scope* parent_scope = parser->session->current_scope;
	union IFF_Header_Flags parent_flags = parent_scope->flags;
	VPS_TYPE_SIZE container_size = 0;
	VPS_TYPE_8U tag_size = IFF_Header_Flags_GetTagLength(parent_flags.as_fields.tag_sizing);
	VPS_TYPE_8U size_len = IFF_Header_Flags_GetSizeLength(parent_flags.as_fields.sizing);
	struct IFF_Tag list_type;
	struct IFF_Tag tag;
	struct IFF_Scope* child_scope = 0;
	struct IFF_Boundary child_boundary;
	char result;

	// 1. If blobbed mode, read container size and update parent boundary.
	if (parent_flags.as_fields.operating == IFF_Header_Operating_BLOBBED)
	{
		result = IFF_Reader_ReadSize
		(
			parser->reader,
			parent_flags.as_fields.sizing,
			parent_flags.as_fields.typing,
			&container_size
		);
		if (!result)
		{
			return 0;
		}

		parent_scope->boundary.level += size_len + container_size;
	}

	// 2. Read LIST type tag.
	result = IFF_Reader_ReadTag
	(
		parser->reader,
		parent_flags.as_fields.tag_sizing,
		&list_type
	);
	if (!result)
	{
		return 0;
	}

	// Type tags are content identifiers; force classification to TAG.
	list_type.type = IFF_TAG_TYPE_TAG;

	// 3. Create and enter child scope.
	IFF_Boundary_Construct(&child_boundary);
	child_boundary.limit = container_size;
	child_boundary.level = tag_size;

	if (!IFF_Scope_Allocate(&child_scope))
	{
		return 0;
	}

	IFF_Scope_Construct
	(
		child_scope,
		parent_flags,
		child_boundary,
		IFF_TAG_SYSTEM_LIST,
		list_type
	);

	IFF_Parser_Session_EnterScope(parser->session, child_scope);

	// 4. Content loop — PROPs, containers, and directives. No direct data chunks.
	while (IFF_Parser_Session_IsActive(parser->session)
		&& IFF_Parser_Session_IsBoundaryOpen(parser->session))
	{
		result = IFF_Reader_ReadTag
		(
			parser->reader,
			parser->session->current_scope->flags.as_fields.tag_sizing,
			&tag
		);
		if (!result)
		{
			break;
		}

		parser->session->current_scope->boundary.level +=
			IFF_Header_Flags_GetTagLength(parser->session->current_scope->flags.as_fields.tag_sizing);

		switch (tag.type)
		{
			case IFF_TAG_TYPE_DIRECTIVE:
			{
				char scope_ended = 0;

				result = PRIVATE_IFF_Parser_Parse_Directive
				(
					parser,
					tag,
					&scope_ended
				);
				if (!result)
				{
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
				if (scope_ended)
				{
					goto list_done;
				}
			}
			break;

			case IFF_TAG_TYPE_CONTAINER:
			{
				result = PRIVATE_IFF_Parser_Parse_Container
				(
					parser,
					tag
				);
				if (!result)
				{
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
			}
			break;

			case IFF_TAG_TYPE_SUBCONTAINER:
			{
				result = PRIVATE_IFF_Parser_Parse_PROP
				(
					parser
				);
				if (!result)
				{
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
			}
			break;

			// Data chunks not allowed directly in LIST.
			case IFF_TAG_TYPE_TAG:
			default:
			{
				IFF_Parser_Session_LeaveScope(parser->session);
				return 0;
			}
		}
	}

list_done:

	IFF_Parser_Session_LeaveScope(parser->session);

	return 1;
}


// --- CAT Container ---

static char PRIVATE_IFF_Parser_Parse_Container_CAT
(
	struct IFF_Parser *parser
)
{
	struct IFF_Scope* parent_scope = parser->session->current_scope;
	union IFF_Header_Flags parent_flags = parent_scope->flags;
	VPS_TYPE_SIZE container_size = 0;
	VPS_TYPE_8U tag_size = IFF_Header_Flags_GetTagLength(parent_flags.as_fields.tag_sizing);
	VPS_TYPE_8U size_len = IFF_Header_Flags_GetSizeLength(parent_flags.as_fields.sizing);
	struct IFF_Tag cat_type;
	struct IFF_Tag tag;
	struct IFF_Scope* child_scope = 0;
	struct IFF_Boundary child_boundary;
	char result;

	// 1. If blobbed mode, read container size and update parent boundary.
	if (parent_flags.as_fields.operating == IFF_Header_Operating_BLOBBED)
	{
		result = IFF_Reader_ReadSize
		(
			parser->reader,
			parent_flags.as_fields.sizing,
			parent_flags.as_fields.typing,
			&container_size
		);
		if (!result)
		{
			return 0;
		}

		parent_scope->boundary.level += size_len + container_size;
	}

	// 2. Read CAT type tag.
	result = IFF_Reader_ReadTag
	(
		parser->reader,
		parent_flags.as_fields.tag_sizing,
		&cat_type
	);
	if (!result)
	{
		return 0;
	}

	// Type tags are content identifiers; force classification to TAG.
	cat_type.type = IFF_TAG_TYPE_TAG;

	// 3. Create and enter child scope.
	IFF_Boundary_Construct(&child_boundary);
	child_boundary.limit = container_size;
	child_boundary.level = tag_size;

	if (!IFF_Scope_Allocate(&child_scope))
	{
		return 0;
	}

	IFF_Scope_Construct
	(
		child_scope,
		parent_flags,
		child_boundary,
		IFF_TAG_SYSTEM_CAT,
		cat_type
	);

	IFF_Parser_Session_EnterScope(parser->session, child_scope);

	// 4. Content loop — nested containers and directives only.
	while (IFF_Parser_Session_IsActive(parser->session)
		&& IFF_Parser_Session_IsBoundaryOpen(parser->session))
	{
		result = IFF_Reader_ReadTag
		(
			parser->reader,
			parser->session->current_scope->flags.as_fields.tag_sizing,
			&tag
		);
		if (!result)
		{
			break;
		}

		parser->session->current_scope->boundary.level +=
			IFF_Header_Flags_GetTagLength(parser->session->current_scope->flags.as_fields.tag_sizing);

		switch (tag.type)
		{
			case IFF_TAG_TYPE_DIRECTIVE:
			{
				char scope_ended = 0;

				result = PRIVATE_IFF_Parser_Parse_Directive
				(
					parser,
					tag,
					&scope_ended
				);
				if (!result)
				{
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
				if (scope_ended)
				{
					goto cat_done;
				}
			}
			break;

			case IFF_TAG_TYPE_CONTAINER:
			{
				result = PRIVATE_IFF_Parser_Parse_Container
				(
					parser,
					tag
				);
				if (!result)
				{
					IFF_Parser_Session_LeaveScope(parser->session);
					return 0;
				}
			}
			break;

			// PROP and data chunks not allowed in CAT.
			case IFF_TAG_TYPE_TAG:
			default:
			{
				IFF_Parser_Session_LeaveScope(parser->session);
				return 0;
			}
		}
	}

cat_done:

	IFF_Parser_Session_LeaveScope(parser->session);

	return 1;
}


// --- Data Chunk Parsing ---

static char PRIVATE_IFF_Parser_Parse_Chunk
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
)
{
	struct IFF_Parser_Session* session = parser->session;
	struct IFF_Scope* scope = session->current_scope;
	union IFF_Header_Flags flags = scope->flags;
	struct IFF_Chunk* chunk = 0;
	struct IFF_ContextualData* contextual_data = 0;
	struct IFF_ChunkDecoder* decoder = 0;
	struct IFF_Chunk_Key lookup_key;
	struct IFF_Parser_State parser_state;
	VPS_TYPE_16S variant_ordering;
	char result;

	// 1. Read the chunk (size + data).
	result = IFF_Reader_ReadChunk
	(
		parser->reader,
		&flags.as_fields,
		&tag,
		&chunk
	);
	if (!result)
	{
		return 0;
	}

	// 2. Track boundary: size field + data payload.
	scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
		+ chunk->size;

	// 3. Handle padding (skip alignment byte for odd-size chunks).
	if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
		&& (chunk->size & 1))
	{
		IFF_Reader_Skip(parser->reader, 1);
		scope->boundary.level += 1;
	}

	// 4. Look up a chunk decoder.
	parser_state.session = session;
	lookup_key.form = scope->container_type;
	lookup_key.prop = tag;

	if (VPS_Dictionary_Find(parser->chunk_decoders, &lookup_key, (void**)&decoder))
	{
		// Decoder found — invoke its lifecycle.
		void* custom_state = 0;

		if (flags.as_fields.structuring & IFF_Header_Flag_Structuring_SHARDING)
		{
			// Deferred lifecycle: flush any pending decoder, then begin a new
			// one and store it for future shard continuation.
			if (!PRIVATE_IFF_Parser_FlushLastDecoder(parser))
			{
				IFF_Chunk_Release(chunk);
				return 0;
			}

			if (decoder->begin_decode)
			{
				if (!decoder->begin_decode(&parser_state, &custom_state))
				{
					IFF_Chunk_Release(chunk);
					return 0;
				}
			}

			if (!decoder->process_shard(&parser_state, custom_state, chunk->data))
			{
				IFF_Chunk_Release(chunk);
				return 0;
			}

			// Store decoder for shard continuation — end_decode is deferred.
			scope->last_chunk_decoder = decoder;
			scope->last_chunk_state = custom_state;
			scope->last_chunk_tag = tag;

			IFF_Chunk_Release(chunk);

			return 1;
		}

		// Immediate lifecycle (SHARDING not set).
		if (decoder->begin_decode)
		{
			if (!decoder->begin_decode(&parser_state, &custom_state))
			{
				IFF_Chunk_Release(chunk);
				return 0;
			}
		}

		if (!decoder->process_shard(&parser_state, custom_state, chunk->data))
		{
			IFF_Chunk_Release(chunk);
			return 0;
		}

		if (decoder->end_decode)
		{
			if (!decoder->end_decode(&parser_state, custom_state, &contextual_data))
			{
				IFF_Chunk_Release(chunk);
				return 0;
			}
		}
	}
	else
	{
		// No decoder — flush any pending shard decoder first (a new unregistered
		// chunk terminates the shard sequence).
		if (flags.as_fields.structuring & IFF_Header_Flag_Structuring_SHARDING)
		{
			if (!PRIVATE_IFF_Parser_FlushLastDecoder(parser))
			{
				IFF_Chunk_Release(chunk);
				return 0;
			}
		}

		// Wrap raw data as contextual data.
		if (!IFF_ContextualData_Allocate(&contextual_data))
		{
			IFF_Chunk_Release(chunk);
			return 0;
		}

		// Clone the data so contextual_data owns its own copy.
		struct VPS_Data* data_clone = 0;
		if (chunk->data)
		{
			VPS_Data_Clone(&data_clone, chunk->data, 0, chunk->data->size);
		}

		IFF_ContextualData_Construct(contextual_data, flags, data_clone);
	}

	// 5. Route the result based on scope context.
	IFF_Tag_Compare(&scope->container_variant, &IFF_TAG_SYSTEM_PROP, &variant_ordering);

	if (variant_ordering == 0)
	{
		// We are inside a PROP — store as a property.
		if (contextual_data)
		{
			IFF_Parser_Session_AddProp
			(
				session,
				&scope->container_type,
				&tag,
				contextual_data
			);
			contextual_data = 0; // Dictionary takes ownership.
		}
	}
	else if (scope->form_decoder && scope->form_decoder->process_chunk && contextual_data)
	{
		// We are inside a FORM with a decoder — pass the chunk to it.
		result = scope->form_decoder->process_chunk
		(
			&parser_state,
			scope->form_state,
			&tag,
			contextual_data
		);
		contextual_data = 0; // Form decoder takes ownership.

		if (!result)
		{
			IFF_Chunk_Release(chunk);
			return 0;
		}
	}
	else if (contextual_data)
	{
		// No handler — release the data.
		IFF_ContextualData_Release(contextual_data);
		contextual_data = 0;
	}

	IFF_Chunk_Release(chunk);

	return 1;
}


// --- Segment Switch ---

static char PRIVATE_IFF_Parser_PushReaderAndSwitch
(
	struct IFF_Parser *parser
	, int new_file_handle
)
{
	struct IFF_Parser_Session *session = parser->session;
	struct IFF_ReaderFrame *frame = 0;
	struct VPS_List_Node *node = 0;
	struct IFF_Reader *new_reader = 0;

	// Circular inclusion guard.
	if (parser->reader_stack->count >= 16)
	{
		return 0;
	}

	// Save current state into a frame.
	if (!IFF_ReaderFrame_Allocate(&frame))
	{
		return 0;
	}

	IFF_ReaderFrame_Construct
	(
		frame,
		parser->reader,
		parser->file_handle,
		session->iff85_locked
	);

	if (!VPS_List_Node_Allocate(&node))
	{
		IFF_ReaderFrame_Release(frame);
		return 0;
	}

	VPS_List_Node_Construct(node, frame);
	VPS_List_AddHead(parser->reader_stack, node);

	// Create a new reader for the included segment.
	if (!IFF_Reader_Allocate(&new_reader))
	{
		goto rollback;
	}

	if (!IFF_Reader_Construct(new_reader, new_file_handle))
	{
		IFF_Reader_Release(new_reader);
		goto rollback;
	}

	parser->reader = new_reader;
	parser->file_handle = new_file_handle;
	session->iff85_locked = 0;

	IFF_Parser_Session_SetState(session, IFF_Parser_SessionState_SegmentSwitch);

	return 1;

rollback:

	// Pop the frame we just pushed and restore state.
	{
		struct VPS_List_Node *popped = 0;

		if (VPS_List_RemoveHead(parser->reader_stack, &popped))
		{
			struct IFF_ReaderFrame *saved = popped->data;

			parser->reader = saved->reader;
			parser->file_handle = saved->file_handle;
			session->iff85_locked = saved->iff85_locked;

			saved->reader = 0;
			saved->file_handle = -1;

			IFF_ReaderFrame_Release(saved);
			VPS_List_Node_Release(popped);
		}
	}

	return 0;
}

static char PRIVATE_IFF_Parser_PopReaderAndRestore
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session *session = parser->session;
	struct VPS_List_Node *node = 0;
	struct IFF_ReaderFrame *frame;

	if (!VPS_List_RemoveHead(parser->reader_stack, &node))
	{
		return 0;
	}

	frame = node->data;

	// Release the current (included) reader and close its file handle.
	IFF_Reader_Release(parser->reader);
	close(parser->file_handle);

	// Restore parent state from the frame.
	parser->reader = frame->reader;
	parser->file_handle = frame->file_handle;
	session->iff85_locked = frame->iff85_locked;

	// Prevent double-free: frame no longer owns these.
	frame->reader = 0;
	frame->file_handle = -1;

	IFF_ReaderFrame_Release(frame);
	VPS_List_Node_Release(node);

	session->parsing_resumed = 1;

	return 1;
}

static char PRIVATE_IFF_Parser_HandleSegmentRef
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
)
{
	struct IFF_Scope *scope = parser->session->current_scope;
	union IFF_Header_Flags flags = scope->flags;
	struct IFF_Chunk *chunk = 0;
	struct VPS_DataReader *dr = 0;
	VPS_TYPE_SIZE num_options = 0;
	VPS_TYPE_SIZE i;
	char has_optional = 0;
	char result;

	// Read the directive chunk.
	result = IFF_Reader_ReadChunk
	(
		parser->reader,
		&flags.as_fields,
		&tag,
		&chunk
	);
	if (!result)
	{
		return 0;
	}

	// Track boundary: size field + data payload.
	scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
		+ chunk->size;

	// Handle padding for odd-length directive data.
	if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
		&& (chunk->size & 1))
	{
		IFF_Reader_Skip(parser->reader, 1);
		scope->boundary.level += 1;
	}

	// If no resolver registered:
	// - strict_references mode: parse the payload to check if any option
	//   is mandatory (id_size > 0). If so, fail.
	// - default mode: consume silently for forward compatibility.
	if (!parser->segment_resolver)
	{
		if (parser->strict_references)
		{
			struct VPS_DataReader *sr = 0;
			VPS_TYPE_SIZE sr_num = 0;
			VPS_TYPE_SIZE sr_i;
			char has_mandatory = 0;

			if (VPS_DataReader_Allocate(&sr) && VPS_DataReader_Construct(sr, chunk->data))
			{
				if (IFF_Reader_ReadPayloadSize(sr, &flags.as_fields, &sr_num))
				{
					for (sr_i = 0; sr_i < sr_num; ++sr_i)
					{
						VPS_TYPE_SIZE sr_id_size = 0;
						if (!IFF_Reader_ReadPayloadSize(sr, &flags.as_fields, &sr_id_size))
						{
							break;
						}
						if (sr_id_size > 0)
						{
							has_mandatory = 1;
							break;
						}
					}
				}
			}

			VPS_DataReader_Release(sr);

			if (has_mandatory)
			{
				IFF_Chunk_Release(chunk);
				return 0;
			}
		}

		IFF_Chunk_Release(chunk);
		return 1;
	}

	// Wrap chunk data in a DataReader.
	if (!VPS_DataReader_Allocate(&dr))
	{
		IFF_Chunk_Release(chunk);
		return 0;
	}

	if (!VPS_DataReader_Construct(dr, chunk->data))
	{
		VPS_DataReader_Release(dr);
		IFF_Chunk_Release(chunk);
		return 0;
	}

	// Read num_options.
	if (!IFF_Reader_ReadPayloadSize(dr, &flags.as_fields, &num_options))
	{
		VPS_DataReader_Release(dr);
		IFF_Chunk_Release(chunk);
		return 0;
	}

	// Iterate options.
	for (i = 0; i < num_options; ++i)
	{
		VPS_TYPE_SIZE id_size = 0;
		struct VPS_Data *id_data = 0;
		int fh = -1;

		if (!IFF_Reader_ReadPayloadSize(dr, &flags.as_fields, &id_size))
		{
			VPS_DataReader_Release(dr);
			IFF_Chunk_Release(chunk);
			return 0;
		}

		// id_size == 0 means optional (skip if unresolved).
		if (id_size == 0)
		{
			has_optional = 1;
			continue;
		}

		// Read identifier bytes.
		if (!VPS_Data_Allocate(&id_data, id_size, id_size))
		{
			VPS_DataReader_Release(dr);
			IFF_Chunk_Release(chunk);
			return 0;
		}

		if (!VPS_DataReader_ReadBytes(dr, id_data->bytes, id_size))
		{
			VPS_Data_Release(id_data);
			VPS_DataReader_Release(dr);
			IFF_Chunk_Release(chunk);
			return 0;
		}

		// Try to resolve this identifier.
		if (parser->segment_resolver(parser->resolver_context, id_data, &fh))
		{
			VPS_Data_Release(id_data);
			VPS_DataReader_Release(dr);
			IFF_Chunk_Release(chunk);

			return PRIVATE_IFF_Parser_PushReaderAndSwitch(parser, fh);
		}

		// Resolution failed for this option, try the next.
		VPS_Data_Release(id_data);
	}

	VPS_DataReader_Release(dr);
	IFF_Chunk_Release(chunk);

	// All options exhausted.
	if (has_optional)
	{
		// Optional reference — skip silently.
		return 1;
	}

	// Mandatory reference could not be resolved.
	return 0;
}


// --- Segment Parsing ---

static char PRIVATE_IFF_Parser_Parse_Segment
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session* session;
	struct IFF_Tag tag;
	union IFF_Header_Flags* current_flags;
	char result;
	char first_tag = 1;

	session = parser->session;
	current_flags = &session->current_scope->flags;

	IFF_Parser_Session_SetState(session, IFF_Parser_SessionState_Segment);

	while (IFF_Parser_Session_IsActive(session))
	{
		if (!IFF_Parser_Session_IsBoundaryOpen(session))
		{
			goto failure;
		}

		current_flags = &session->current_scope->flags;

		result = IFF_Reader_ReadTag
		(
			parser->reader,
			current_flags->as_fields.tag_sizing,
			&tag
		);

		if (!result)
		{
			if (IFF_Reader_IsActive(parser->reader))
			{
				goto failure;
			}

			// Clean end of stream — check if we are inside an inclusion.
			if (parser->reader_stack->count > 0)
			{
				PRIVATE_IFF_Parser_PopReaderAndRestore(parser);
				IFF_Parser_Session_SetState(session, IFF_Parser_SessionState_SegmentSwitch);
				return 1;
			}

			IFF_Parser_Session_SetState(session, IFF_Parser_SessionState_Complete);

			return 1;
		}

		// Bootstrap: if the first tag is a container (not an ' IFF' directive),
		// this is an implicit IFF-85 stream. Lock the session to reject all
		// directives except filler ('    ').
		if (first_tag)
		{
			first_tag = 0;

			if (!session->parsing_resumed && tag.type == IFF_TAG_TYPE_CONTAINER)
			{
				session->iff85_locked = 1;
			}

			session->parsing_resumed = 0;
		}

		switch (tag.type)
		{
			case IFF_TAG_TYPE_DIRECTIVE:
			{
				// Intercept ' REF' before generic directive handling.
				VPS_TYPE_16S ref_ordering;
				IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_REF, &ref_ordering);

				if (ref_ordering == 0)
				{
					result = PRIVATE_IFF_Parser_HandleSegmentRef(parser, tag);
					if (!result)
					{
						goto failure;
					}
					if (session->session_state == IFF_Parser_SessionState_SegmentSwitch)
					{
						return 1;
					}
					break;
				}

				{
					char scope_ended = 0;

					result = PRIVATE_IFF_Parser_Parse_Directive
					(
						parser,
						tag,
						&scope_ended
					);

					if (!result)
					{
						goto failure;
					}

					// ' END' at global scope during inclusion → resume parent.
					if (scope_ended && parser->reader_stack->count > 0)
					{
						PRIVATE_IFF_Parser_PopReaderAndRestore(parser);
						IFF_Parser_Session_SetState(session, IFF_Parser_SessionState_SegmentSwitch);
						return 1;
					}
				}
			}
			break;

			case IFF_TAG_TYPE_CONTAINER:
			{
				result = PRIVATE_IFF_Parser_Parse_Container
				(
					parser,
					tag
				);

				if (!result)
				{
					goto failure;
				}
			}
			break;

			default:
			{
				goto failure;
			}
		}
	}

	return 1;

failure:
	IFF_Parser_Session_SetState(session, IFF_Parser_SessionState_Failed);

	return 0;
}


// --- Public Entry Point ---

char IFF_Parser_Scan
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session* session;

	if (!parser || !parser->session || !parser->reader)
	{
		return 0;
	}

	session = parser->session;

	while (1)
	{
		if (session->session_state == IFF_Parser_SessionState_Failed
			|| session->session_state == IFF_Parser_SessionState_Complete)
		{
			break;
		}

		PRIVATE_IFF_Parser_Parse_Segment(parser);
	}

	return session->session_state == IFF_Parser_SessionState_Complete;
}

char IFF_Parser_SetSegmentResolver
(
	struct IFF_Parser *parser,
	IFF_SegmentResolverFn resolver,
	void *context
)
{
	if (!parser)
	{
		return 0;
	}

	parser->segment_resolver = resolver;
	parser->resolver_context = context;

	return 1;
}
