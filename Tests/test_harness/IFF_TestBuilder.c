#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataWriter.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>

#include "IFF_TestBuilder.h"

// --- Private helpers ---

static char PRIVATE_WriteTag
(
	struct IFF_TestBuilder *b
	, const char *tag
	, char is_directive
)
{
	unsigned char buf[16];
	VPS_TYPE_8U len = b->tag_length;

	memset(buf, ' ', 16);

	if (is_directive)
	{
		// Left-pad: place tag chars at end of the field.
		VPS_TYPE_8U tag_len = (VPS_TYPE_8U)strlen(tag);
		if (tag_len > len) tag_len = len;
		memcpy(buf + (len - tag_len), tag, tag_len);
	}
	else
	{
		// Right-pad: place tag chars at start.
		VPS_TYPE_8U tag_len = (VPS_TYPE_8U)strlen(tag);
		if (tag_len > len) tag_len = len;
		memcpy(buf, tag, tag_len);
	}

	return VPS_DataWriter_WriteBytes(b->writer, buf, len);
}

static char PRIVATE_WriteSize
(
	struct IFF_TestBuilder *b
	, VPS_TYPE_SIZE size
)
{
	unsigned char buf[8];

	switch (b->size_length)
	{
		case 2:
			if (b->is_le)
				VPS_Endian_Write16ULE(buf, (VPS_TYPE_16U)size);
			else
				VPS_Endian_Write16UBE(buf, (VPS_TYPE_16U)size);
			break;

		case 8:
			if (b->is_le)
				VPS_Endian_Write64ULE(buf, (VPS_TYPE_64U)size);
			else
				VPS_Endian_Write64UBE(buf, (VPS_TYPE_64U)size);
			break;

		default: // 4
			if (b->is_le)
				VPS_Endian_Write32ULE(buf, (VPS_TYPE_32U)size);
			else
				VPS_Endian_Write32UBE(buf, (VPS_TYPE_32U)size);
			break;
	}

	return VPS_DataWriter_WriteBytes(b->writer, buf, b->size_length);
}

static char PRIVATE_PatchSize
(
	struct IFF_TestBuilder *b
	, VPS_TYPE_SIZE offset
	, VPS_TYPE_SIZE size
)
{
	unsigned char buf[8];

	switch (b->size_length)
	{
		case 2:
			if (b->is_le)
				VPS_Endian_Write16ULE(buf, (VPS_TYPE_16U)size);
			else
				VPS_Endian_Write16UBE(buf, (VPS_TYPE_16U)size);
			break;

		case 8:
			if (b->is_le)
				VPS_Endian_Write64ULE(buf, (VPS_TYPE_64U)size);
			else
				VPS_Endian_Write64UBE(buf, (VPS_TYPE_64U)size);
			break;

		default: // 4
			if (b->is_le)
				VPS_Endian_Write32ULE(buf, (VPS_TYPE_32U)size);
			else
				VPS_Endian_Write32UBE(buf, (VPS_TYPE_32U)size);
			break;
	}

	memcpy(b->buffer->bytes + offset, buf, b->size_length);

	return 1;
}

static char PRIVATE_WritePadding
(
	struct IFF_TestBuilder *b
	, VPS_TYPE_SIZE data_size
)
{
	static const unsigned char zero = 0;

	if (data_size & 1)
	{
		return VPS_DataWriter_WriteBytes(b->writer, &zero, 1);
	}

	return 1;
}

// --- Lifecycle ---

char IFF_TestBuilder_Allocate
(
	struct IFF_TestBuilder **builder
)
{
	struct IFF_TestBuilder *b;

	if (!builder) return 0;

	b = calloc(1, sizeof(struct IFF_TestBuilder));
	if (!b) return 0;

	if (!VPS_Data_Allocate(&b->buffer, 256, 0))
	{
		goto cleanup;
	}

	if (!VPS_DataWriter_Allocate(&b->writer))
	{
		goto cleanup;
	}

	*builder = b;

	return 1;

cleanup:

	IFF_TestBuilder_Release(b);

	return 0;
}

char IFF_TestBuilder_Construct
(
	struct IFF_TestBuilder *b
)
{
	if (!b) return 0;

	if (!VPS_Data_Construct(b->buffer)) return 0;
	if (!VPS_DataWriter_Construct(b->writer, b->buffer)) return 0;

	// Default to IFF-85 settings.
	b->tag_length = 4;
	b->size_length = 4;
	b->is_le = 0;
	b->is_progressive = 0;
	b->depth = 0;

	return 1;
}

char IFF_TestBuilder_Deconstruct
(
	struct IFF_TestBuilder *b
)
{
	if (!b) return 0;

	VPS_DataWriter_Deconstruct(b->writer);
	VPS_Data_Deconstruct(b->buffer);

	return 1;
}

char IFF_TestBuilder_Release
(
	struct IFF_TestBuilder *b
)
{
	if (b)
	{
		IFF_TestBuilder_Deconstruct(b);
		VPS_DataWriter_Release(b->writer);
		VPS_Data_Release(b->buffer);
		free(b);
	}

	return 1;
}

// --- Structure builders ---

char IFF_TestBuilder_AddHeader
(
	struct IFF_TestBuilder *b
	, const struct IFF_Header *header
)
{
	unsigned char payload[12];

	if (!b || !header) return 0;

	// Write the ' IFF' directive tag.
	if (!PRIVATE_WriteTag(b, " IFF", 1)) return 0;

	// The header payload is always 12 bytes:
	//   version (2 BE) + revision (2 BE) + flags (8 bytes)
	VPS_Endian_Write16UBE(payload, header->version);
	VPS_Endian_Write16UBE(payload + 2, header->revision);
	VPS_Endian_Write64UBE(payload + 4, header->flags.as_int);

	// Write size (12) in current config, then the payload.
	if (!PRIVATE_WriteSize(b, 12)) return 0;
	if (!VPS_DataWriter_WriteBytes(b->writer, payload, 12)) return 0;

	// Update builder config from the header flags.
	b->tag_length = IFF_Header_Flags_GetTagLength(header->flags.as_fields.tag_sizing);
	b->size_length = IFF_Header_Flags_GetSizeLength(header->flags.as_fields.sizing);
	b->is_le = (header->flags.as_fields.typing & IFF_Header_Flag_Typing_LITTLE_ENDIAN) ? 1 : 0;
	b->is_progressive = (header->flags.as_fields.operating == IFF_Header_Operating_PROGRESSIVE) ? 1 : 0;

	return 1;
}

char IFF_TestBuilder_BeginContainer
(
	struct IFF_TestBuilder *b
	, const char *variant
	, const char *type
)
{
	if (!b || !variant || !type) return 0;
	if (b->depth >= IFF_TEST_BUILDER_MAX_DEPTH) return 0;

	// Write the variant tag (FORM, LIST, CAT , PROP) — always data-style (right-padded).
	if (!PRIVATE_WriteTag(b, variant, 0)) return 0;

	if (!b->is_progressive)
	{
		// Blobbed mode: record patch offset, write placeholder size.
		b->patch_offsets[b->depth] = b->buffer->limit;
		if (!PRIVATE_WriteSize(b, 0)) return 0;
	}

	// Write the type tag (right-padded data tag).
	if (!PRIVATE_WriteTag(b, type, 0)) return 0;

	b->depth++;

	return 1;
}

char IFF_TestBuilder_EndContainer
(
	struct IFF_TestBuilder *b
)
{
	if (!b || b->depth <= 0) return 0;

	b->depth--;

	if (b->is_progressive)
	{
		// Write ' END' directive + size 0.
		if (!PRIVATE_WriteTag(b, " END", 1)) return 0;
		if (!PRIVATE_WriteSize(b, 0)) return 0;
	}
	else
	{
		// Blobbed: patch the size field.
		VPS_TYPE_SIZE patch_offset = b->patch_offsets[b->depth];
		VPS_TYPE_SIZE content_start = patch_offset + b->size_length;
		VPS_TYPE_SIZE content_size = b->buffer->limit - content_start;

		if (!PRIVATE_PatchSize(b, patch_offset, content_size)) return 0;
	}

	return 1;
}

char IFF_TestBuilder_AddChunk
(
	struct IFF_TestBuilder *b
	, const char *tag
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	if (!b || !tag) return 0;
	if (size > 0 && !data) return 0;

	if (!PRIVATE_WriteTag(b, tag, 0)) return 0;
	if (!PRIVATE_WriteSize(b, size)) return 0;

	if (size > 0)
	{
		if (!VPS_DataWriter_WriteBytes(b->writer, data, size)) return 0;
	}

	if (!PRIVATE_WritePadding(b, size)) return 0;

	return 1;
}

char IFF_TestBuilder_AddDirective
(
	struct IFF_TestBuilder *b
	, const char *tag
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	if (!b || !tag) return 0;
	if (size > 0 && !data) return 0;

	if (!PRIVATE_WriteTag(b, tag, 1)) return 0;
	if (!PRIVATE_WriteSize(b, size)) return 0;

	if (size > 0)
	{
		if (!VPS_DataWriter_WriteBytes(b->writer, data, size)) return 0;
	}

	if (!PRIVATE_WritePadding(b, size)) return 0;

	return 1;
}

char IFF_TestBuilder_GetResult
(
	struct IFF_TestBuilder *b
	, struct VPS_Data **out_data
)
{
	if (!b || !out_data) return 0;

	*out_data = b->buffer;

	return 1;
}
