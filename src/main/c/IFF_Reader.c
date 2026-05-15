#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_DataPump.h>
#include <IFF/IFF_DataTap.h>
#include <IFF/IFF_Chunk.h>
#include <IFF/IFF_Reader.h>

/**
 * @brief Interprets a raw byte buffer as an integer based on current config.
 */
static char IFF_Reader_PRIVATE_InterpretSize
(
	enum IFF_Header_Sizing sizing,
	enum IFF_Header_Flag_Typing typing,
	const unsigned char* raw_bytes,
	VPS_TYPE_SIZE* out_size
)
{
	char is_le = typing & IFF_Header_Flag_Typing_LITTLE_ENDIAN;
	char is_unsigned = typing & IFF_Header_Flag_Typing_UNSIGNED_SIZES;

	switch (sizing)
	{
		case IFF_Header_Sizing_16:
		{
			if (is_unsigned)
			{
				*out_size = is_le ? VPS_Endian_Read16ULE(raw_bytes) : VPS_Endian_Read16UBE(raw_bytes);
			}
			else
			{
				*out_size = (VPS_TYPE_SIZE)(VPS_TYPE_SPAN)(is_le ? (VPS_TYPE_16S)VPS_Endian_Read16ULE(raw_bytes) : (VPS_TYPE_16S)VPS_Endian_Read16UBE(raw_bytes));
			}
		}
		break;

		case IFF_Header_Sizing_64:
		{
			// On a 32-bit host, this will truncate. The parser needs to either stop or provide a soft 64 bit VPS_TIPE_SIZE implementation
			if (is_unsigned)
			{
				*out_size = (VPS_TYPE_SIZE)(is_le ? VPS_Endian_Read64ULE(raw_bytes) : VPS_Endian_Read64UBE(raw_bytes));
			}
			else
			{
				*out_size = (VPS_TYPE_SIZE)(VPS_TYPE_SPAN)(is_le ? (VPS_TYPE_64S)VPS_Endian_Read64ULE(raw_bytes) : (VPS_TYPE_64S)VPS_Endian_Read64UBE(raw_bytes));
			}
		}
		break;

		default: // IFF_Header_Sizing_32
		{
			if (is_unsigned)
			{
				*out_size = is_le ? VPS_Endian_Read32ULE(raw_bytes) : VPS_Endian_Read32UBE(raw_bytes);
			}
			else
			{
				*out_size = (VPS_TYPE_SIZE)(VPS_TYPE_SPAN)(is_le ? (VPS_TYPE_32S)VPS_Endian_Read32ULE(raw_bytes) : (VPS_TYPE_32S)VPS_Endian_Read32UBE(raw_bytes));
			}
		}
	}

	return 1;
}

char IFF_Reader_Allocate
(
	struct IFF_Reader** item
)
{
	struct IFF_Reader* reader;
	if (!item)
	{
		return 0;
	}

	reader = calloc
	(
		1,
		sizeof(struct IFF_Reader)
	);
	if (!reader)
	{
		*item = 0;
		return 0;
	}

	// Allocate the entire decorator stack that this reader owns.
	if (!IFF_DataTap_Allocate(&reader->tap))
	{
		goto cleanup;
	}

	*item = reader;
	return 1;

cleanup:

	*item = 0;
	IFF_Reader_Release(reader);

	return  0;
}

char IFF_Reader_Construct
(
	struct IFF_Reader* item
	, int fh
)
{
	if (!item)
	{
		return 0;
	}

	// Construct the underlying stack, passing the file handle down.
	if (!IFF_DataTap_Construct(item->tap, fh))
	{
		return 0;
	}

	// TODO: Allocate and construct the content_decoders dictionary when needed.
	//		 The Spec hints to different encodings but only Base256 is currenty defined
	item->content_decoders = 0;

	return 1;
}

char IFF_Reader_ConstructFromData
(
	struct IFF_Reader* item
	, const struct VPS_Data *source
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_DataTap_ConstructFromData(item->tap, source))
	{
		return 0;
	}

	item->content_decoders = 0;

	return 1;
}

char IFF_Reader_Deconstruct
(
	struct IFF_Reader* item
)
{
	if (!item) return 0;

	// Deconstruct the owned reader stack.
	IFF_DataTap_Deconstruct(item->tap);
	VPS_Dictionary_Release(item->content_decoders);
	item->content_decoders = 0;

	return 1;
}

char IFF_Reader_Release
(
	struct IFF_Reader* item
)
{
	if (item)
	{
		IFF_Reader_Deconstruct(item);
		IFF_DataTap_Release(item->tap);
		free(item);
	}
	return 1;
}

char IFF_Reader_ReadTag
(
	struct IFF_Reader* reader
	, enum IFF_Header_TagSizing tag_sizing
	, struct IFF_Tag* tag
)
{
	struct VPS_Data* raw_data = 0;
	VPS_TYPE_8U tag_size_in_bytes;

	if (!reader || !tag)
	{
		return 0;
	}

	tag_size_in_bytes = IFF_Header_Flags_GetTagLength(tag_sizing);
	if (tag_size_in_bytes == 0)
	{
		return 0;
	}

	// 1. Read raw bytes from the next layer down.
	if (!IFF_DataTap_ReadRaw(reader->tap, tag_size_in_bytes, &raw_data))
	{
		return 0;
	}

	// 2. Classify the tag type and construct the canonical form.
	enum IFF_Tag_Type type = (raw_data->bytes[0] == ' ') ? IFF_TAG_TYPE_DIRECTIVE : IFF_TAG_TYPE_TAG;
	char result = IFF_Tag_Construct(tag, raw_data->bytes, tag_size_in_bytes, type);

	VPS_Data_Release(raw_data);

	if (!result)
	{
		return 0;
	}

	// 3. Post-classify: reclassify known container and subcontainer tags.
	//    ReadTag initially marks all non-directives as TAG. We now compare
	//    the canonical data against the known system container patterns
	//    (FORM, LIST, CAT, PROP) and reclassify the type accordingly.
	if (type == IFF_TAG_TYPE_TAG)
	{
		if (memcmp(tag->data, IFF_TAG_SYSTEM_FORM.data, IFF_TAG_CANONICAL_SIZE) == 0
			|| memcmp(tag->data, IFF_TAG_SYSTEM_LIST.data, IFF_TAG_CANONICAL_SIZE) == 0
			|| memcmp(tag->data, IFF_TAG_SYSTEM_CAT.data, IFF_TAG_CANONICAL_SIZE) == 0)
		{
			tag->type = IFF_TAG_TYPE_CONTAINER;
		}
		else if (memcmp(tag->data, IFF_TAG_SYSTEM_PROP.data, IFF_TAG_CANONICAL_SIZE) == 0)
		{
			tag->type = IFF_TAG_TYPE_SUBCONTAINER;
		}
	}

	return 1;
}

char IFF_Reader_ReadSize
(
	struct IFF_Reader* reader
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_SIZE* size
)
{
	struct VPS_Data* raw_data = 0;
	VPS_TYPE_8U size_in_bytes;

	if (!reader || !size) return 0;
	*size = 0;

	size_in_bytes = IFF_Header_Flags_GetSizeLength(sizing);
	if (size_in_bytes == 0) return 0;

	// 1. Read raw bytes from the next layer down.
	if (!IFF_DataTap_ReadRaw(reader->tap, size_in_bytes, &raw_data))
	{
		return 0;
	}

	// 2. Interpret the raw bytes based on the current configuration.
	char result = IFF_Reader_PRIVATE_InterpretSize(sizing, typing, raw_data->bytes, size);

	VPS_Data_Release(raw_data);
	return result;
}

char IFF_Reader_ReadData
(
	struct IFF_Reader* reader
	, enum IFF_Header_Encoding encoding
	, VPS_TYPE_SIZE size
	, struct VPS_Data** out_data
)
{
	if (!reader || !out_data) return 0;

	// If content decoding were implemented, the logic would go here.
	// We would read the raw data, then pass it through the appropriate
	// decoder from the `content_decoders` dictionary based on `encoding`.

	// For now, we just pass through to the checked reader.
	return IFF_DataTap_ReadRaw(reader->tap, size, out_data);
}

char IFF_Reader_Skip
(
	struct IFF_Reader* reader
	, VPS_TYPE_SIZE bytes_to_skip
)
{
	if (!reader)
	{
		return 0;
	}

	return IFF_DataTap_Skip
	(
		reader->tap
		, bytes_to_skip
	);
}

char IFF_Reader_IsActive
(
	struct IFF_Reader* reader
)
{
	VPS_TYPE_SIZE remaining = 0;

	if (!reader || !reader->tap || !reader->tap->pump || !reader->tap->pump->data_reader)
	{
		return 0;
	}

	VPS_DataReader_Remaining(reader->tap->pump->data_reader, &remaining);

	return remaining > 0;
}

char IFF_Reader_ReadChunk
(
	struct IFF_Reader* reader,
	const struct IFF_Header_Flags_Fields* config,
	struct IFF_Tag *tag,
	struct IFF_Chunk** out_chunk
)
{
	if (!reader || !config || !tag || !out_chunk) return 0;

	*out_chunk = 0;
	VPS_TYPE_SIZE size = 0;
	struct VPS_Data* data = 0;
	struct IFF_Chunk* chunk = 0;

	// 1. Read Size using the granular primitive
	if (!IFF_Reader_ReadSize(reader, config->sizing, config->typing, &size))
	{
		// Failed to read size after reading a tag, this is a file corruption error.
		return 0;
	}

	// 2. Read Data payload using the granular primitive
	if (size > 0)
	{
		if (!IFF_Reader_ReadData(reader, config->encoding, size, &data))
		{
			// Failed to read the data payload after getting tag and size.
			// This is a file corruption error.
			return 0;
		}
	}

	// 3. Assemble the final chunk object
	if (!IFF_Chunk_Allocate(&chunk))
	{
		VPS_Data_Release(data); // Must release the data if chunk allocation fails
		return 0;
	}

	// The IFF_Chunk takes ownership of the data pointer.
	if (!IFF_Chunk_Construct(chunk, tag, size, data))
	{
		// Construction failed. The chunk does not own the data yet,
		// so we must release both resources manually.
		VPS_Data_Release(data);
		IFF_Chunk_Release(chunk);

		return 0;
	}

	*out_chunk = chunk;

	return 1;
}

/**
 * @brief Reads a size field from a VPS_DataReader using the current scope's config.
 */
char IFF_Reader_ReadPayloadSize
(
	struct VPS_DataReader* dr,
	const struct IFF_Header_Flags_Fields* config,
	VPS_TYPE_SIZE* out_size
)
{
	VPS_TYPE_8U size_len = IFF_Header_Flags_GetSizeLength(config->sizing);
	unsigned char buf[8];
	VPS_TYPE_SIZE remaining = 0;

	VPS_DataReader_Remaining(dr, &remaining);
	if (remaining < size_len)
	{
		return 0;
	}

	if (!VPS_DataReader_ReadBytes(dr, buf, size_len))
	{
		return 0;
	}

	return IFF_Reader_PRIVATE_InterpretSize(config->sizing, config->typing, buf, out_size);
}

char IFF_Reader_StartChecksumSpan
(
	struct IFF_Reader* reader
	, const struct IFF_Header_Flags_Fields* config
	, const struct VPS_Data* chk_payload
)
{
	struct VPS_DataReader* dr = 0;
	struct VPS_Set* algorithm_ids = 0;
	VPS_TYPE_SIZE version = 0;
	VPS_TYPE_SIZE num_ids = 0;
	VPS_TYPE_SIZE i;
	char result;

	if (!reader || !config || !chk_payload)
	{
		return 0;
	}

	// Wrap the payload in a DataReader for sequential access.
	if (!VPS_DataReader_Allocate(&dr))
	{
		return 0;
	}

	if (!VPS_DataReader_Construct(dr, (struct VPS_Data*)chk_payload))
	{
		VPS_DataReader_Release(dr);
		return 0;
	}

	// Read version (currently expect 1).
	if (!IFF_Reader_ReadPayloadSize(dr, config, &version))
	{
		goto cleanup;
	}

	if (version != 1)
	{
		goto cleanup;
	}

	// Read number of algorithm identifiers.
	if (!IFF_Reader_ReadPayloadSize(dr, config, &num_ids))
	{
		goto cleanup;
	}

	// Build a VPS_Set of algorithm identifier strings.
	if (!VPS_Set_Allocate(&algorithm_ids, 7))
	{
		goto cleanup;
	}

	VPS_Set_Construct
	(
		algorithm_ids,
		(char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_Data,
		(char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_Data,
		(char(*)(void*))VPS_Data_Release,
		2, 75, 8
	);

	for (i = 0; i < num_ids; ++i)
	{
		VPS_TYPE_SIZE id_len = 0;
		struct VPS_Data* id_data = 0;

		if (!IFF_Reader_ReadPayloadSize(dr, config, &id_len))
		{
			goto cleanup;
		}

		// Allocate a VPS_Data for the identifier string (+ null terminator).
		if (!VPS_Data_Allocate(&id_data, id_len + 1, id_len + 1))
		{
			goto cleanup;
		}

		if (!VPS_DataReader_ReadBytes(dr, id_data->bytes, id_len))
		{
			VPS_Data_Release(id_data);
			goto cleanup;
		}

		id_data->bytes[id_len] = '\0';

		if (!VPS_Set_Add(algorithm_ids, id_data))
		{
			VPS_Data_Release(id_data);
			goto cleanup;
		}
	}

	// Delegate to DataTap.
	result = IFF_DataTap_StartSpan(reader->tap, algorithm_ids);
	VPS_Set_Release(algorithm_ids);
	VPS_DataReader_Release(dr);

	return result;

cleanup:

	VPS_Set_Release(algorithm_ids);
	VPS_DataReader_Release(dr);

	return 0;
}

char IFF_Reader_EndChecksumSpan
(
	struct IFF_Reader* reader
	, const struct IFF_Header_Flags_Fields* config
	, const struct VPS_Data* sum_payload
)
{
	struct VPS_DataReader* dr = 0;
	struct VPS_Dictionary* expected_checksums = 0;
	VPS_TYPE_SIZE version = 0;
	VPS_TYPE_SIZE num_ids = 0;
	VPS_TYPE_SIZE i;
	char result;

	if (!reader || !config || !sum_payload)
	{
		return 0;
	}

	// Wrap the payload in a DataReader for sequential access.
	if (!VPS_DataReader_Allocate(&dr))
	{
		return 0;
	}

	if (!VPS_DataReader_Construct(dr, (struct VPS_Data*)sum_payload))
	{
		VPS_DataReader_Release(dr);
		return 0;
	}

	// Read version.
	if (!IFF_Reader_ReadPayloadSize(dr, config, &version))
	{
		goto cleanup;
	}

	if (version != 1)
	{
		goto cleanup;
	}

	// Read number of entries.
	if (!IFF_Reader_ReadPayloadSize(dr, config, &num_ids))
	{
		goto cleanup;
	}

	// Build a dictionary mapping identifier strings to expected checksums.
	if (!VPS_Dictionary_Allocate(&expected_checksums, 7))
	{
		goto cleanup;
	}

	VPS_Dictionary_Construct
	(
		expected_checksums,
		(char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_String,
		(char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_String,
		0,                                          // keys are interior pointers to id_data->bytes; released via data_release
		(char(*)(void*))VPS_Data_Release,           // release expected checksum VPS_Data
		2, 75, 8
	);

	for (i = 0; i < num_ids; ++i)
	{
		VPS_TYPE_SIZE id_len = 0;
		VPS_TYPE_SIZE sum_len = 0;
		struct VPS_Data* id_data = 0;
		struct VPS_Data* sum_data = 0;

		// Read algorithm identifier.
		if (!IFF_Reader_ReadPayloadSize(dr, config, &id_len))
		{
			goto cleanup;
		}

		if (!VPS_Data_Allocate(&id_data, id_len + 1, id_len + 1))
		{
			goto cleanup;
		}

		if (!VPS_DataReader_ReadBytes(dr, id_data->bytes, id_len))
		{
			VPS_Data_Release(id_data);
			goto cleanup;
		}

		id_data->bytes[id_len] = '\0';

		// Read expected checksum.
		if (!IFF_Reader_ReadPayloadSize(dr, config, &sum_len))
		{
			VPS_Data_Release(id_data);
			goto cleanup;
		}

		if (!VPS_Data_Allocate(&sum_data, sum_len, sum_len))
		{
			VPS_Data_Release(id_data);
			goto cleanup;
		}

		if (sum_len > 0)
		{
			if (!VPS_DataReader_ReadBytes(dr, sum_data->bytes, sum_len))
			{
				VPS_Data_Release(id_data);
				VPS_Data_Release(sum_data);
				goto cleanup;
			}
		}

		// Add to dictionary. Key is the string pointer inside id_data.
		// EndSpan looks up by algorithm->identifier (a const char*), so we
		// use string hash/compare. The key is id_data->bytes (the null-terminated string).
		if (!VPS_Dictionary_Add(expected_checksums, id_data->bytes, sum_data))
		{
			VPS_Data_Release(id_data);
			VPS_Data_Release(sum_data);
			goto cleanup;
		}

		// The dictionary now references id_data->bytes as the key, but nobody
		// owns the id_data container. We need id_data->bytes to stay alive until
		// the dictionary is released. Transfer ownership of the bytes to the
		// dictionary by leaking the VPS_Data wrapper but keeping the bytes.
		// Detach so VPS_Data_Release won't free the bytes.
		id_data->own_bytes = 0;
		VPS_Data_Release(id_data);
	}

	// Delegate to DataTap for verification.
	result = IFF_DataTap_EndSpan(reader->tap, expected_checksums);

	// Clean up. The dictionary release will free the expected checksum VPS_Data values.
	// The keys (string pointers) were detached from id_data and need manual cleanup.
	// Since the dictionary has no key_release, we need to handle this.
	// Actually, since we set own_bytes=0 and released the VPS_Data wrappers, the raw
	// bytes are still allocated on the heap (from VPS_Data_Allocate). We need to free
	// them. Let's iterate the dictionary and free the keys.
	{
		VPS_TYPE_SIZE b;
		for (b = 0; b < expected_checksums->buckets; ++b)
		{
			struct VPS_List* bucket = expected_checksums->bucket_vector[b];
			if (!bucket) continue;
			struct VPS_List_Node* node = bucket->head;
			while (node)
			{
				struct VPS_Dictionary_Entry* entry = node->data;
				free(entry->key);
				entry->key = 0;
				node = node->next;
			}
		}
	}

	VPS_Dictionary_Release(expected_checksums);
	VPS_DataReader_Release(dr);

	return result;

cleanup:

	VPS_Dictionary_Release(expected_checksums);
	VPS_DataReader_Release(dr);

	return 0;
}
