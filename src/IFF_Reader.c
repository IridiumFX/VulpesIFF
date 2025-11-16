#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Decoder.h>
#include <vulpes/VPS_Decoder_Base256.h>
#include <vulpes/VPS_StreamReader.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Reader.h>

char IFF_Reader_Allocate
(
	struct IFF_Reader **item
)
{
	struct IFF_Reader *reader;

	if (!item)
	{
		return 0;
	}

	reader = calloc
	(
		1
		, sizeof(struct IFF_Reader)
	);
	if (!reader)
	{
		return 0;
	}

	VPS_Decoder_Allocate
	(
		&reader->base256_decoder
	);
	if (!reader->base256_decoder)
	{
		goto cleanup;
	}

	VPS_Data_Allocate
	(
		&reader->data_buffer
		, 128
		, 0
	);
	if (!reader->data_buffer)
	{
		goto cleanup;
	}

	VPS_DataReader_Allocate
	(
		&reader->data_reader
	);
	if (!reader->data_reader)
	{
		goto cleanup;
	}

	VPS_StreamReader_Allocate
	(
		&reader->stream_reader
	);
	if (!reader->stream_reader)
	{
		goto cleanup;
	}

	*item = reader;

	return 1;

cleanup:

	IFF_Reader_Release
	(
		reader
	);

	return 0;
}

char IFF_Reader_Construct
(
	struct IFF_Reader *item
	, int fh
)
{
	if (!item)
	{
		return 0;
	}

	// Construct the I/O pipeline that this reader will manage.
	if
	(
		!VPS_Decoder_Base256_Construct
		(
			item->base256_decoder
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_Data_Construct
		(
			item->data_buffer
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_DataReader_Construct
		(
			item->data_reader
			, item->data_buffer
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_StreamReader_Construct
		(
			item->stream_reader
			, item->data_buffer
			, fh
			, 0 // Let the stream reader create its own raw buffer
			, 0
		)
	)
	{
		return 0;
	}

	return 1;
}

char IFF_Reader_Deconstruct
(
	struct IFF_Reader *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_StreamReader_Deconstruct
	(
		item->stream_reader
	);

	VPS_DataReader_Deconstruct
	(
		item->data_reader
	);

	VPS_Data_Deconstruct
	(
		item->data_buffer
	);

	VPS_Decoder_Deconstruct
	(
		item->base256_decoder
	);

	return 1;
}

char IFF_Reader_Release
(
	struct IFF_Reader *item
)
{
	if (item)
	{
		IFF_Reader_Deconstruct
		(
			item
		);

		VPS_StreamReader_Release
		(
			item->stream_reader
		);

		VPS_DataReader_Release
		(
			item->data_reader
		);

		VPS_Data_Release
		(
			item->data_buffer
		);

		VPS_Decoder_Release
		(
			item->base256_decoder
		);

		free
		(
			item
		);
	}
	return 1;
}

static char IFF_Reader_PRIVATE_EnsureDataAvailable
(
	struct IFF_Reader *reader,
	VPS_TYPE_SIZE bytes_needed
)
{
	VPS_TYPE_SIZE bytes_available = 0;

	VPS_Data_Compact(reader->data_buffer);

	if (reader->data_buffer->limit >= bytes_needed)
	{
		return 1;
	}

	if
	(
		!VPS_StreamReader_Read
		(
			reader->stream_reader
			, bytes_needed
			, 0
			, 0
			, 0
			, &bytes_available
			, reader->base256_decoder
			, 0
		)
	)
	{
		return 0; // Read error
	}

	return (char)(bytes_available >= bytes_needed);
}

char IFF_Reader_ReadTag
(
	struct IFF_Reader *reader
	, enum IFF_Header_TagSizing tag_sizing
	, struct IFF_Tag *tag
)
{
	unsigned char raw_tag_buffer[IFF_TAG_CANONICAL_SIZE];
	enum IFF_Tag_Type type;
	VPS_TYPE_8U tag_size;

	tag_size = IFF_Header_Flags_GetTagLength
	(
		tag_sizing
	); 

	if (!reader || !tag || tag_size == 0)
	{
		return 0;
	}

	if (!IFF_Reader_PRIVATE_EnsureDataAvailable(reader, tag_size))
	{
		return 0;
	}

	if
	(
		!VPS_DataReader_ReadBytes
		(
			reader->data_reader
			, raw_tag_buffer
			, tag_size
		)
	)
	{
		return 0;
	}

	type = (raw_tag_buffer[0] == ' ') ? IFF_TAG_TYPE_DIRECTIVE : IFF_TAG_TYPE_TAG;

	return IFF_Tag_Construct
	(
		tag
		, raw_tag_buffer
		, tag_size
		, type
	);
}

// --- Size Reader Abstraction ---

typedef char (*size_reader_func)(struct VPS_DataReader*, VPS_TYPE_64U*);

// --- Unsigned Readers ---
static char read_size_16u_be(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_16U t; if(!VPS_DataReader_Read16UBE(r, &t)) return 0; *s = t; return 1; }
static char read_size_16u_le(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_16U t; if(!VPS_DataReader_Read16ULE(r, &t)) return 0; *s = t; return 1; }
static char read_size_32u_be(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_32U t; if(!VPS_DataReader_Read32UBE(r, &t)) return 0; *s = t; return 1; }
static char read_size_32u_le(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_32U t; if(!VPS_DataReader_Read32ULE(r, &t)) return 0; *s = t; return 1; }
static char read_size_64u_be(struct VPS_DataReader *r, VPS_TYPE_64U *s) { return VPS_DataReader_Read64UBE(r, s); }
static char read_size_64u_le(struct VPS_DataReader *r, VPS_TYPE_64U *s) { return VPS_DataReader_Read64ULE(r, s); }

// --- Signed Readers ---
static char read_size_16s_be(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_16S t; if(!VPS_DataReader_Read16SBE(r, &t)) return 0; *s = (VPS_TYPE_64U)(VPS_TYPE_64S)t; return 1; }
static char read_size_16s_le(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_16S t; if(!VPS_DataReader_Read16SLE(r, &t)) return 0; *s = (VPS_TYPE_64U)(VPS_TYPE_64S)t; return 1; }
static char read_size_32s_be(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_32S t; if(!VPS_DataReader_Read32SBE(r, &t)) return 0; *s = (VPS_TYPE_64U)(VPS_TYPE_64S)t; return 1; }
static char read_size_32s_le(struct VPS_DataReader *r, VPS_TYPE_64U *s) { VPS_TYPE_32S t; if(!VPS_DataReader_Read32SLE(r, &t)) return 0; *s = (VPS_TYPE_64U)(VPS_TYPE_64S)t; return 1; }
static char read_size_64s_be(struct VPS_DataReader *r, VPS_TYPE_64U *s) { return VPS_DataReader_Read64SBE(r, (VPS_TYPE_64S*)s); }
static char read_size_64s_le(struct VPS_DataReader *r, VPS_TYPE_64U *s) { return VPS_DataReader_Read64SLE(r, (VPS_TYPE_64S*)s); }


static size_reader_func get_size_reader
(
	enum IFF_Header_Sizing sizing,
	enum IFF_Header_Flag_Typing typing
)
{
	char is_le = typing & IFF_Header_Flag_Typing_LITTLE_ENDIAN;
    char is_unsigned = typing & IFF_Header_Flag_Typing_UNSIGNED_SIZES;

	switch (sizing)
	{
		case IFF_Header_Sizing_16:
		{
			if (is_unsigned) return is_le ? read_size_16u_le : read_size_16u_be;
			return is_le ? read_size_16s_le : read_size_16s_be;
		}
		break;

		case IFF_Header_Sizing_64:
		{
			if (is_unsigned) return is_le ? read_size_64u_le : read_size_64u_be;
			return is_le ? read_size_64s_le : read_size_64s_be;
		}
		break;

		default: // IFF_Header_Sizing_32
		{
			if (is_unsigned) return is_le ? read_size_32u_le : read_size_32u_be;
			return is_le ? read_size_32s_le : read_size_32s_be;
		}
	}
}

char IFF_Reader_ReadSize
(
	struct IFF_Reader *reader
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_64U *size
)
{
	size_reader_func size_reader;
	char result;

	VPS_TYPE_8U size_in_bytes = IFF_Header_Flags_GetSizeLength
	(
		sizing
	);

	if (!reader || !size || size_in_bytes == 0)
	{
		return 0;
	}
	*size = 0;

	if (!IFF_Reader_PRIVATE_EnsureDataAvailable(reader, size_in_bytes))
	{
		return 0;
	}

	size_reader = get_size_reader
	(
		sizing,
		typing
	);
	if (!size_reader)
	{
		return 0; // Should be unreachable
	}

	result = size_reader
	(
		reader->data_reader
		, size
	);

	return result;
}

char IFF_Reader_ReadData
(
	struct IFF_Reader *reader
	, VPS_TYPE_64U size
	, struct VPS_Data **out_data
)
{
	if (!reader || !out_data || size == 0)
	{
		return 0;
	}

	if (!IFF_Reader_PRIVATE_EnsureDataAvailable(reader, size))
	{
		return 0;
	}

	if
	(
		!VPS_Data_Clone
		(
			out_data
			, reader->data_buffer
			, reader->data_buffer->position
			, size
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_Data_Seek
		(
			reader->data_buffer
			, size
			, SEEK_CUR
		)
	)
	{
		VPS_Data_Release(*out_data);
		*out_data = 0;

		return 0;
	}

	return 1;
}

char IFF_Reader_Seek
(
	struct IFF_Reader *reader
	, VPS_TYPE_64S offset
)
{
	if (!reader || !reader->stream_reader || offset < 0)
	{
		return 0;
	}

	return VPS_StreamReader_Seek
	(
		reader->stream_reader
		, offset
		, SEEK_CUR
	);
}
