#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_WritePump.h>
#include <IFF/IFF_WriteTap.h>
#include <IFF/IFF_Writer.h>

IFF_TYPE_RESULT IFF_Writer_Allocate
(
	struct IFF_Writer **item
)
{
	struct IFF_Writer *writer;

	if (!item)
	{
		return IFF_FAIL;
	}

	writer = calloc(1, sizeof(struct IFF_Writer));
	if (!writer)
	{
		return IFF_FAIL;
	}

	if (IFF_WriteTap_Allocate(&writer->tap))
	{
		goto cleanup;
	}

	*item = writer;

	return IFF_OK;

cleanup:

	IFF_Writer_Release(writer);

	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_Writer_Construct
(
	struct IFF_Writer *item
	, int file_handle
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	if (IFF_WriteTap_Construct(item->tap, file_handle))
	{
		return IFF_FAIL;
	}

	item->content_encoders = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Writer_ConstructToData
(
	struct IFF_Writer *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	if (IFF_WriteTap_ConstructToData(item->tap))
	{
		return IFF_FAIL;
	}

	item->content_encoders = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Writer_GetOutputData
(
	struct IFF_Writer *writer
	, struct VPS_Data **out_data
)
{
	if (!writer)
	{
		return IFF_FAIL;
	}

	return IFF_WriteTap_GetOutputData(writer->tap, out_data);
}

IFF_TYPE_RESULT IFF_Writer_Deconstruct
(
	struct IFF_Writer *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	IFF_WriteTap_Deconstruct(item->tap);
	VPS_Dictionary_Release(item->content_encoders);
	item->content_encoders = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Writer_Release
(
	struct IFF_Writer *item
)
{
	if (item)
	{
		IFF_Writer_Deconstruct(item);
		IFF_WriteTap_Release(item->tap);
		free(item);
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Writer_WriteTag
(
	struct IFF_Writer *writer
	, enum IFF_Header_TagSizing tag_sizing
	, const struct IFF_Tag *tag
)
{
	VPS_TYPE_8U tag_length;

	if (!writer || !tag)
	{
		return IFF_FAIL;
	}

	tag_length = IFF_Header_Flags_GetTagLength(tag_sizing);
	if (tag_length == 0)
	{
		return IFF_FAIL;
	}

	/*
	 * Tags are stored in canonical 16-byte form. For writing, we emit the
	 * appropriate number of bytes based on tag_sizing:
	 * - Data tags (TAG, CONTAINER, SUBCONTAINER): right-padded, so emit from offset 0.
	 * - Directive tags: left-padded, so emit from offset (16 - tag_length).
	 */
	if (tag->type == IFF_TAG_TYPE_DIRECTIVE)
	{
		return IFF_WriteTap_WriteRaw
		(
			writer->tap
			, tag->data + (IFF_TAG_CANONICAL_SIZE - tag_length)
			, tag_length
		);
	}
	else
	{
		return IFF_WriteTap_WriteRaw
		(
			writer->tap
			, tag->data
			, tag_length
		);
	}
}

IFF_TYPE_RESULT IFF_Writer_WriteSize
(
	struct IFF_Writer *writer
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_SIZE size
)
{
	unsigned char buf[8];
	VPS_TYPE_8U size_length;
	char is_le;

	if (!writer)
	{
		return IFF_FAIL;
	}

	size_length = IFF_Header_Flags_GetSizeLength(sizing);
	if (size_length == 0)
	{
		return IFF_FAIL;
	}

	// Refuse sizes the selected width cannot represent instead of wrapping
	// silently on the wire.
	if (size_length < 8 && (size >> (size_length * 8)) != 0)
	{
		return IFF_FAIL;
	}

	is_le = typing & IFF_Header_Flag_Typing_LITTLE_ENDIAN;

	switch (sizing)
	{
		case IFF_Header_Sizing_16:
		{
			if (is_le)
			{
				VPS_Endian_Write16ULE(buf, (VPS_TYPE_16U)size);
			}
			else
			{
				VPS_Endian_Write16UBE(buf, (VPS_TYPE_16U)size);
			}
		}
		break;

		case IFF_Header_Sizing_64:
		{
			if (is_le)
			{
				VPS_Endian_Write64ULE(buf, (VPS_TYPE_64U)size);
			}
			else
			{
				VPS_Endian_Write64UBE(buf, (VPS_TYPE_64U)size);
			}
		}
		break;

		default: /* IFF_Header_Sizing_32 */
		{
			if (is_le)
			{
				VPS_Endian_Write32ULE(buf, (VPS_TYPE_32U)size);
			}
			else
			{
				VPS_Endian_Write32UBE(buf, (VPS_TYPE_32U)size);
			}
		}
	}

	return IFF_WriteTap_WriteRaw(writer->tap, buf, size_length);
}

IFF_TYPE_RESULT IFF_Writer_WriteData
(
	struct IFF_Writer *writer
	, enum IFF_Header_Encoding encoding
	, const struct VPS_Data *data
)
{
	if (!writer || !data)
	{
		return IFF_FAIL;
	}

	(void)encoding;

	return IFF_WriteTap_WriteData(writer->tap, data);
}

IFF_TYPE_RESULT IFF_Writer_WriteChunk
(
	struct IFF_Writer *writer
	, const struct IFF_Header_Flags_Fields *config
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
)
{
	VPS_TYPE_SIZE data_size;

	if (!writer || !config || !tag)
	{
		return IFF_FAIL;
	}

	data_size = data ? data->limit : 0;

	if (IFF_Writer_WriteTag(writer, config->tag_sizing, tag))
	{
		return IFF_FAIL;
	}

	if (IFF_Writer_WriteSize(writer, config->sizing, config->typing, data_size))
	{
		return IFF_FAIL;
	}

	if (data_size > 0)
	{
		if (IFF_Writer_WriteData(writer, config->encoding, data))
		{
			return IFF_FAIL;
		}
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Writer_WritePadding
(
	struct IFF_Writer *writer
	, const struct IFF_Header_Flags_Fields *config
	, VPS_TYPE_SIZE data_size
)
{
	static const unsigned char zero = 0;

	if (!writer || !config)
	{
		return IFF_FAIL;
	}

	if (config->structuring & IFF_Header_Flag_Structuring_NO_PADDING)
	{
		return IFF_OK;
	}

	if (data_size & 1)
	{
		return IFF_WriteTap_WriteRaw(writer->tap, &zero, 1);
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Writer_Flush
(
	struct IFF_Writer *writer
)
{
	if (!writer)
	{
		return IFF_FAIL;
	}

	return IFF_WriteTap_Flush(writer->tap);
}
