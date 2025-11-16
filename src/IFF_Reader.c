#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_DataTap.h>
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
			if (is_unsigned) *out_size = is_le ? VPS_Endian_Read16ULE(raw_bytes) : VPS_Endian_Read16UBE(raw_bytes);
			else *out_size = (VPS_TYPE_64U)(VPS_TYPE_64S)(is_le ? (VPS_TYPE_16S)VPS_Endian_Read16ULE(raw_bytes) : (VPS_TYPE_16S)VPS_Endian_Read16UBE(raw_bytes));
			return 1;
		case IFF_Header_Sizing_64:
			if (is_unsigned) *out_size = is_le ? VPS_Endian_Read64ULE(raw_bytes) : VPS_Endian_Read64UBE(raw_bytes);
			else *out_size = (VPS_TYPE_64U)(is_le ? (VPS_TYPE_64S)VPS_Endian_Read64ULE(raw_bytes) : (VPS_TYPE_64S)VPS_Endian_Read64UBE(raw_bytes));
			return 1;
		default: // IFF_Header_Sizing_32
			if (is_unsigned) *out_size = is_le ? VPS_Endian_Read32ULE(raw_bytes) : VPS_Endian_Read32UBE(raw_bytes);
			else *out_size = (VPS_TYPE_64U)(VPS_TYPE_64S)(is_le ? (VPS_TYPE_32S)VPS_Endian_Read32ULE(raw_bytes) : (VPS_TYPE_32S)VPS_Endian_Read32UBE(raw_bytes));
			return 1;
	}
	return 0; // Should be unreachable
}

char IFF_Reader_Allocate
(
	struct IFF_Reader** item
)
{
	struct IFF_Reader* reader;
	if (!item) return 0;

	reader = calloc(1, sizeof(struct IFF_Reader));
	if (!reader) return 0;

	// Allocate the entire decorator stack that this reader owns.
	if (!IFF_DataTap_Allocate(&reader->tap))
	{
		IFF_Reader_Release(reader);
		return 0;
	}

	*item = reader;
	return 1;
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

	if (!reader || !tag) return 0;

	tag_size_in_bytes = IFF_Header_Flags_GetTagLength(tag_sizing);
	if (tag_size_in_bytes == 0) return 0;

	// 1. Read raw bytes from the next layer down.
	if (!IFF_DataTap_ReadRaw(reader->tap, tag_size_in_bytes, &raw_data))
	{
		return 0;
	}

	// 2. Interpret the raw bytes to create the canonical tag.
	enum IFF_Tag_Type type = (raw_data->bytes[0] == ' ') ? IFF_TAG_TYPE_DIRECTIVE : IFF_TAG_TYPE_TAG;
	char result = IFF_Tag_Construct(tag, raw_data->bytes, tag_size_in_bytes, type);

	VPS_Data_Release(raw_data);
	return result;
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
	if (reader)
	{
		return 0;
	}

	return IFF_DataTap_Skip
	(
		reader->tap
		, bytes_to_skip
	);
}
