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
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_Parser_State.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Scope_State.h>

// Helper to check if a canonical tag is all spaces.
static char is_tag_blank(struct IFF_Tag* tag)
{
    for(int i=0; i<IFF_TAG_CANONICAL_SIZE; ++i) {
        if (tag->data[i] != ' ') return 0;
    }
    return 1;
}

/**
 * @brief Finalizes the currently active chunk operation, if any.
 * @details This is the lynchpin of the progressive decoding pipeline.
 *          It takes a completed data chunk, calls the chunk decoder's end_decode,
 *          and feeds the resulting contextual data directly to the active
 *          FORM decoder for immediate processing.
 */
static char IFF_Parser_PRIVATE_FinalizeActiveChunk
(
	struct IFF_Parser_State *state
)
{
    if (!state->active_chunk_decoder) return 1;

	struct IFF_ContextualData *contextual_data = 0;
    if (state->active_chunk_decoder->end_decode)
    {
		state->active_chunk_decoder->end_decode(state, state->active_chunk_state, &contextual_data);
    }

    // If the chunk decoder produced data, feed it to the active FORM decoder.
    if (contextual_data)
    {
        struct IFF_Scope_State *current_scope = state->scope_stack->head->data;
        if (current_scope->form_decoder && current_scope->form_decoder->process_chunk)
        {
            current_scope->form_decoder->process_chunk(
                state,
                current_scope->form_state,
                &state->active_chunk_tag,
                contextual_data
            );
        }
        else
        {
            // If there's no active form decoder (e.g. we are inside a PROP),
            // the contextual data is discarded as it has no consumer.
            IFF_ContextualData_Release(contextual_data);
        }
    }

	// Reset the active chunk state, ready for the next operation.
	state->active_chunk_decoder = 0;
	state->active_chunk_state = 0;
	memset(&state->active_chunk_tag, 0, sizeof(struct IFF_Tag));

	return 1;
}

/**
 * @brief Performs a hierarchical lookup to find the most appropriate chunk decoder.
 * @details Implements the IFF-2025 spec's "pull" semantics by searching for a
 *          decoder in the correct order of precedence:
 *          1. A type-specific PROP context.
 *          2. A wildcard PROP context.
 *          3. The current FORM's container type.
 */
static char IFF_Parser_PRIVATE_FindChunkDecoder(
    struct IFF_Parser *parser,
    struct IFF_Parser_State *state,
    struct IFF_Tag *chunk_tag,
    struct IFF_ChunkDecoder **out_decoder
)
{
    struct IFF_Chunk_Key key;
    struct IFF_Scope_State *current_scope = state->scope_stack->head->data;
    key.prop = *chunk_tag;

    // --- Hierarchical Lookup ---

    // 1. First, search for a decoder specific to the current container's type.
    //    This handles both direct children of a FORM and properties from a
    //    type-specific PROP (e.g., key: {'ILBM', 'BMHD'}).
    if (!is_tag_blank(&current_scope->container_type))
    {
        key.form = current_scope->container_type;
        if (VPS_Dictionary_Find(parser->chunk_decoders, &key, (void**)out_decoder))
        {
            return 1; // Found the most specific decoder.
        }
    }

    // 2. If not found, fall back to searching for a wildcard decoder.
    //    This handles properties from a wildcard PROP (e.g., key: {'    ', 'CMAP'}).
    IFF_Tag_Construct(&key.form, (const unsigned char*)"    ", 4, IFF_TAG_TYPE_TAG);
    return VPS_Dictionary_Find(parser->chunk_decoders, &key, (void**)out_decoder);
}

/**
 * @brief The private, recursive core of the IFF parser engine.
 * @details This function iterates through a stream, reading components one by one
 *          within the boundaries of the current scope.
 */
static char IFF_Parser_PRIVATE_Scan
(
	struct IFF_Parser *parser,
	struct IFF_Parser_State *state
)
{
	VPS_TYPE_64U chunk_size;
	struct IFF_Scope_State *current_scope;

	if (!parser || !state || !state->reader)
	{
		return 0;
	}

	// The main data-driven parsing loop.
	while (1)
	{
		struct IFF_Tag current_tag;
		VPS_TYPE_16S ordering;

		// 1. Get the current scope and check for boundary conditions.
		current_scope = state->scope_stack->head->data;
		if (current_scope->boundary_size > 0 && current_scope->bytes_scanned >= current_scope->boundary_size)
		{
			break; // Reached the end of a sized container.
		}

		// 2. Read the next tag.
		if (!IFF_Reader_ReadTag(state->reader, &current_tag))
		{
			break; // End of stream or read error.
		}
		current_scope->bytes_scanned += IFF_Header_Flags_GetTagLength(state->active_header_flags);

		// 3. Handle Directives (space-prefixed tags)
		if (current_tag.type == IFF_TAG_TYPE_DIRECTIVE)
		{
			IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_IFF, &ordering);
			if (ordering == 0) // It's an ' IFF' configuration directive.
			{
				VPS_TYPE_64U header_data_size;
				struct VPS_Data *header_data = 0;
				struct VPS_DataReader header_reader;

				if (!IFF_Reader_ReadSize(state->reader, &header_data_size)) break;
				current_scope->bytes_scanned += IFF_Header_Flags_GetSizeLength(state->active_header_flags);

				if (IFF_Reader_ReadData(state->reader, header_data_size, &header_data))
				{
					struct IFF_Header header;
					VPS_DataReader_Construct(&header_reader, header_data);

					if (VPS_DataReader_Read32UBE(&header_reader, (VPS_TYPE_32U*)&header.version) &&
						VPS_DataReader_Read16UBE(&header_reader, &header.revision) &&
						VPS_DataReader_Read64UBE(&header_reader, &header.flags.as_int))
					{
						IFF_Parser_State_SetFlags(state, header.flags);
					}
					VPS_Data_Release(header_data);
				}
				current_scope->bytes_scanned += header_data_size;
				continue;
			}

			IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_END, &ordering);
			if (ordering == 0) // It's an ' END' directive.
			{
				IFF_Parser_PRIVATE_FinalizeActiveChunk(state);
				return 1; // End of a progressive container.
			}

			// Handle other directives (like '    ' in filler mode) or skip unknown ones.
			if (!IFF_Reader_ReadSize(state->reader, &chunk_size)) break;
			current_scope->bytes_scanned += IFF_Header_Flags_GetSizeLength(state->active_header_flags);
			IFF_Reader_Seek(state->reader, (VPS_TYPE_64S)chunk_size);
			current_scope->bytes_scanned += chunk_size;
			continue;
		}

		// --- It's a data chunk or container ---

		// If this chunk is NOT a shard, it signals the end of any previous sharded operation.
		IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_SHARD, &ordering);
		char is_shard = (ordering == 0) && (current_scope->flags.as_fields.structuring & IFF_Header_Flag_Structuring_SHARDING);
		if (!is_shard)
		{
			IFF_Parser_PRIVATE_FinalizeActiveChunk(state);
		}

		// 4. Read the chunk/container size.
		if (!IFF_Reader_ReadSize(state->reader, &chunk_size))
		{
			return 0; // Malformed file
		}
		current_scope->bytes_scanned += IFF_Header_Flags_GetSizeLength(state->active_header_flags);

		// 5. Dispatch to a container or chunk handler
		IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_FORM, &ordering);
		char is_form = (ordering == 0);
		IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_LIST, &ordering);
		char is_list = (ordering == 0);
		IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_CAT, &ordering);
		char is_cat = (ordering == 0);
		IFF_Tag_Compare(&current_tag, &IFF_TAG_SYSTEM_PROP, &ordering);
		char is_prop = (ordering == 0);

		if (is_form || is_list || is_cat || is_prop)
		{
			// --- It's a Container ---
			struct IFF_Tag container_type;
			VPS_TYPE_8U type_tag_size = IFF_Header_Flags_GetTagLength(state->active_header_flags);

			if (!IFF_Reader_ReadTag(state->reader, &container_type)) return 0;
			current_scope->bytes_scanned += type_tag_size;

            // SPEC VALIDATION: FORM type tag cannot be blank.
            if (is_form && is_tag_blank(&container_type)) {
                return 0; // Malformed file: FORM type cannot be blank.
            }

            // SPEC VALIDATION: Homogeneous LIST/CAT containers must contain matching FORM types.
            if (is_form && !is_tag_blank(&current_scope->container_type)) {
                VPS_TYPE_16S type_ordering;
                IFF_Tag_Compare(&current_scope->container_type, &container_type, &type_ordering);
                if (type_ordering != 0) {
                    return 0; // Malformed file: FORM type does not match parent container type.
                }
            }

			// PROP containers are special: their contents are parsed in the *current* scope.
			if (is_prop)
			{
				VPS_TYPE_64U prop_content_size = chunk_size - type_tag_size;
				VPS_TYPE_64U prop_bytes_scanned = 0;

				// Sub-loop to parse the data properties within the PROP container.
				while (prop_bytes_scanned < prop_content_size)
				{
					struct IFF_Tag prop_item_tag;
					VPS_TYPE_64U prop_item_size;
					struct VPS_Data *prop_item_data = 0;
					struct IFF_ContextualData *contextual_data = 0;
					struct IFF_Chunk_Key *key = 0;

					if (!IFF_Reader_ReadTag(state->reader, &prop_item_tag)) break;
					prop_bytes_scanned += IFF_Header_Flags_GetTagLength(state->active_header_flags);

					if (!IFF_Reader_ReadSize(state->reader, &prop_item_size)) break;
					prop_bytes_scanned += IFF_Header_Flags_GetSizeLength(state->active_header_flags);

					if (!IFF_Reader_ReadData(state->reader, prop_item_size, &prop_item_data)) break;
					prop_bytes_scanned += prop_item_size;

					// Package the raw data and current flags for lazy decoding.
					if (!IFF_ContextualData_Allocate(&contextual_data)) { VPS_Data_Release(prop_item_data); break; }
					IFF_ContextualData_Construct(contextual_data, state->active_header_flags, prop_item_data);

					// --- THIS IS THE CRITICAL FIX ---
					// The key for a property is a composite of the PROP's type and the property's own tag.
					if (!IFF_Chunk_Key_Allocate(&key)) { IFF_ContextualData_Release(contextual_data); break; }
					key->form = container_type; // The type of the PROP ('ILBM' or '    ')
					key->prop = prop_item_tag;  // The tag of the property ('CMAP')
					VPS_ScopedDictionary_Add(state->props, key, contextual_data);

					if ((prop_item_size % 2 != 0) && !(current_scope->flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING))
					{
						IFF_Reader_Seek(state->reader, 1);
						prop_bytes_scanned++;
					}
				}
				// The parent scope's counter is updated with the full size of the PROP chunk's content.
				current_scope->bytes_scanned += prop_content_size;
				continue;
			}

			// --- Handle FORM, LIST, CAT ---
			IFF_Parser_State_EnterScope(state, current_tag, container_type);
			struct IFF_Scope_State* new_scope = state->scope_stack->head->data;

			// If it's a FORM, find its decoder and begin the progressive build.
			if (is_form)
			{
				struct IFF_FormDecoder *decoder = 0;
				if (VPS_Dictionary_Find(parser->form_decoders, &container_type, (void**)&decoder) && decoder->begin_decode)
				{
					new_scope->form_decoder = decoder;
					decoder->begin_decode(state, &new_scope->form_state);
				}
			}

			if (state->active_header_flags.as_fields.operating == IFF_Header_Operating_BLOBBED) {
				new_scope->boundary_size = chunk_size - type_tag_size;
			} else {
				new_scope->boundary_size = 0; // Progressive mode
			}

			// Recursively scan the content of the container.
			IFF_Parser_PRIVATE_Scan(parser, state);

			// After the container is fully scanned, finalize its FORM decoder, if any.
			struct IFF_Scope_State* child_scope = new_scope; // For clarity
			if (child_scope->form_decoder && child_scope->form_decoder->end_decode)
			{
				void* final_entity = 0;
				child_scope->form_decoder->end_decode(state, child_scope->form_state, &final_entity);

				// If the FORM produced a final object, pass it to the parent FORM
				// via the dedicated `process_nested_form` event handler.
				if (final_entity)
				{
					struct IFF_Scope_State* parent_scope = state->scope_stack->head->next->data;
					if (parent_scope->form_decoder && parent_scope->form_decoder->process_nested_form)
					{
						parent_scope->form_decoder->process_nested_form(
							state,
							parent_scope->form_state,
							&child_scope->container_type,
							final_entity
						);
					}
				}
			}

			IFF_Parser_State_LeaveScope(state);
		}
		else
		{
			// --- It's a Data Chunk ---

            // SPEC VALIDATION: Data properties are not permitted directly in LIST or CAT containers.
            if (is_tag_blank(&current_scope->container_variant)) return 0; // Should be unreachable, root is validated.
            VPS_TYPE_16S variant_ordering;
            IFF_Tag_Compare(&current_scope->container_variant, &IFF_TAG_SYSTEM_LIST, &variant_ordering);
            if (variant_ordering == 0) return 0; // Malformed
            IFF_Tag_Compare(&current_scope->container_variant, &IFF_TAG_SYSTEM_CAT, &variant_ordering);
            if (variant_ordering == 0) return 0; // Malformed

			struct IFF_ChunkDecoder *chunk_decoder;

			if (is_shard)
			{
				chunk_decoder = state->active_chunk_decoder;
			}
			else
			{
				struct IFF_Chunk_Key key;
				IFF_Parser_PRIVATE_FindChunkDecoder(parser, state, &current_tag, &chunk_decoder);
			}

			if (chunk_decoder)
			{
				if (!is_shard && chunk_decoder->begin_decode)
				{
					chunk_decoder->begin_decode(state, &state->active_chunk_state);
					state->active_chunk_decoder = chunk_decoder;
					state->active_chunk_tag = current_tag;
				}

				struct VPS_Data *chunk_data = 0;
				if (IFF_Reader_ReadData(state->reader, chunk_size, &chunk_data))
				{
					chunk_decoder->process_shard(state, state->active_chunk_state, chunk_data);
				}
			}
			else
			{
				IFF_Reader_Seek(state->reader, (VPS_TYPE_64S)chunk_size);
			}
		}

		current_scope->bytes_scanned += chunk_size;

		// Handle optional padding for the chunk/container we just processed.
		if ((chunk_size % 2 != 0) && !(current_scope->flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING))
		{
			IFF_Reader_Seek(state->reader, 1);
			current_scope->bytes_scanned++;
		}
	}

	// If we exit the loop, it means we hit EOF or a container boundary.
	IFF_Parser_PRIVATE_FinalizeActiveChunk(state);

	return 1;
}

/**
 * @brief The public entry point for parsing an IFF file.
 * @details This function performs the initial bootstrap, determines the file type,
 *          and then kicks off the main recursive scan.
 */
char IFF_Parser_Scan
(
	struct IFF_Parser *parser,
	struct IFF_Parser_State *state
)
{
    if (!parser || !state || !state->reader)
    {
        return 0;
    }

    // --- Bootstrap Logic ---
    // This only runs once to establish the root parsing context.
    // It determines if the file starts with an IFF-2025 directive or if it's
    // a classic IFF-85 file, then lets the main loop handle all parsing.

    struct IFF_Tag first_tag;
    if (!IFF_Reader_ReadTag(state->reader, &first_tag))
    {
        return 1; // Empty file is not an error.
    }

    VPS_TYPE_16S ordering;
    IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_IFF, &ordering);
    if (ordering == 0)
    {
        // The file starts with an ' IFF' directive. We consume it to set the root context.
        VPS_TYPE_64U header_data_size;
        struct VPS_Data *header_data = 0;
        struct VPS_DataReader header_reader;

        if (!IFF_Reader_ReadSize(state->reader, &header_data_size)) return 0;

        if (IFF_Reader_ReadData(state->reader, header_data_size, &header_data))
        {
            struct IFF_Header header;
            VPS_DataReader_Construct(&header_reader, header_data);

            if (VPS_DataReader_Read32UBE(&header_reader, (VPS_TYPE_32U*)&header.version) &&
                VPS_DataReader_Read16UBE(&header_reader, &header.revision) &&
                VPS_DataReader_Read64UBE(&header_reader, &header.flags.as_int))
            {
                IFF_Parser_State_SetFlags(state, header.flags);
            }
            VPS_Data_Release(header_data);
        }
    }
    else
    {
        // The file does not start with ' IFF', so it must be IFF-85.
        // We "un-read" the tag by rewinding the reader's internal buffer position.
        // This is stream-safe as it does not seek the underlying file handle.
        VPS_TYPE_8U tag_size = IFF_Header_Flags_GetTagLength(state->active_header_flags);
        VPS_Data_Seek(state->reader->data_buffer, -tag_size, SEEK_CUR);
    }

    // With the root context established, kick off the main recursive scan.
    // The main loop will now parse the first actual container.
    return IFF_Parser_PRIVATE_Scan(parser, state);
}

char IFF_Parser_Allocate
(
	struct IFF_Parser **item
)
{
	struct IFF_Parser *subject;

	if (!item)
	{
		return 0;
	}

	subject = calloc(1, sizeof(struct IFF_Parser));
	if (!subject)
	{
		return 0;
	}

	if (!VPS_Dictionary_Allocate(&subject->form_decoders, 17))
	{
		goto failure;
	}

	if (!VPS_Dictionary_Allocate(&subject->chunk_decoders, 17))
	{
		goto failure;
	}

	*item = subject;

	return 1;

failure:

	IFF_Parser_Release(subject);

	return 0;
}

char IFF_Parser_Construct
(
	struct IFF_Parser *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Construct
	(
		item->form_decoders
		, (char (*)(void *, VPS_TYPE_SIZE *)) IFF_Tag_Hash
		, (char (*)(void *, void *, VPS_TYPE_16S *)) IFF_Tag_Compare
		, (char (*)(void *)) IFF_Tag_Release
		, 0 // Processors are not owned by the dictionary
		, 2
		, 7500
		, 8
	);
	VPS_Dictionary_Construct
	(
		item->chunk_decoders
		, (char (*)(void *, VPS_TYPE_SIZE *)) IFF_Chunk_Key_Hash
		, (char (*)(void *, void *, VPS_TYPE_16S *)) IFF_Chunk_Key_Compare
		, (char (*)(void *)) IFF_Chunk_Key_Release
		, 0 // Processors are not owned by the dictionary
		, 2
		, 7500
		, 8
	);

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

	VPS_Dictionary_Deconstruct
	(
		item->form_decoders
	);
	VPS_Dictionary_Deconstruct
	(
		item->chunk_decoders
	);

	return 1;
}

char IFF_Parser_Release
(
	struct IFF_Parser *item
)
{
	if (item)
	{
		VPS_Dictionary_Release
		(
			item->chunk_decoders
		);
		VPS_Dictionary_Release
		(
			item->form_decoders
		);
		free(item);
	}

	return 1;
}

char IFF_Parser_Attach
(
	struct IFF_Parser *factory,
	int file_handle,
	struct IFF_Parser_State **state
)
{
	struct IFF_Parser_State *parser_state;
	char result;

	if (!factory || !state)
	{
		return 0;
	}

	result = IFF_Parser_State_Allocate(&parser_state);
	if (!result)
	{
		return 0;
	}

	result = IFF_Parser_State_Construct(parser_state, factory, file_handle, IFF_HEADER_FLAGS_1985);
	if (!result)
	{
		goto failure;
	}

	*state = parser_state;

	return 1;

failure:

	IFF_Parser_State_Release(parser_state);

	return 0;
}

char IFF_Parser_RegisterFormDecoder
(
	struct IFF_Parser *item
	, const unsigned char *raw_form_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_FormDecoder *decoder
)
{
	struct IFF_Tag *form_tag;

	if (!item || !item->form_decoders || !raw_form_tag || !decoder)
	{
		return 0;
	}

	// The parser creates and will own the key.
	if (!IFF_Tag_Allocate(&form_tag))
	{
		return 0;
	}

	if (!IFF_Tag_Construct(form_tag, raw_form_tag, raw_tag_size, IFF_TAG_TYPE_TAG))
	{
		IFF_Tag_Release(form_tag);
		return 0;
	}

	// Add to the dictionary. The dictionary now owns the key via its key_release callback.
	return VPS_Dictionary_Add(item->form_decoders, form_tag, decoder);
}

char IFF_Parser_RegisterChunkDecoder
(
	struct IFF_Parser *item
	, const unsigned char *raw_form_tag
	, const unsigned char *raw_chunk_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_ChunkDecoder *decoder
)
{
	struct IFF_Chunk_Key *key;

	if (!item || !item->chunk_decoders || !raw_form_tag || !raw_chunk_tag || !decoder)
	{
		return 0;
	}

	// The parser creates and will own the key.
	if (!IFF_Chunk_Key_Allocate(&key))
	{
		return 0;
	}

	// Construct the composite key from the raw tag data.
	if (!IFF_Chunk_Key_Construct(key, raw_form_tag, raw_chunk_tag, raw_tag_size))
	{
		IFF_Chunk_Key_Release(key);
		return 0;
	}

	// Add to the dictionary. The dictionary now owns the key via its key_release callback.
	return VPS_Dictionary_Add(item->chunk_decoders, key, decoder);
}
