#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Chunk.h>
#include <IFF/IFF_DirectiveResult.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Directive_IFF_Processor.h>

char IFF_Directive_IFF_Process
(
	const struct IFF_Chunk* chunk,
	struct IFF_DirectiveResult *result
)
{
	struct IFF_Header header;
	struct VPS_DataReader reader;

	if (!chunk || !chunk->data || !result)
	{
		return 0;
	}

	// Use a data reader to safely parse the chunk's payload.
	VPS_DataReader_Construct(&reader, chunk->data);

	if (!VPS_DataReader_Read16UBE(&reader, &header.version) ||
		!VPS_DataReader_Read16UBE(&reader, &header.revision) ||
		!VPS_DataReader_Read64UBE(&reader, &header.flags.as_int))
	{
		// The chunk data is malformed.
		result->action = IFF_ACTION_HALT;
		result->payload.error_code = IFF_ERROR_MALFORMED_DATA;
		return 1;
	}

	// --- Version Validation ---
	// Version=0 means IFF-85: lock to IFF-85 mode with default flags.
	if (header.version == IFF_Header_Version_1985)
	{
		result->action = IFF_ACTION_LOCK_IFF85;
		return 1;
	}

	// Only version 40 (IFF-2025) is supported beyond IFF-85.
	if (header.version != IFF_Header_Version_2025)
	{
		result->action = IFF_ACTION_HALT;
		result->payload.error_code = IFF_ERROR_UNSUPPORTED_FEATURE;
		return 1;
	}

	// --- Flag Field Validation ---
	// Every flag group is an enumeration (or bit set) the specification
	// defines exhaustively. A value outside those definitions cannot be
	// honored — the widths and semantics it implies are unknown, so
	// applying it would misparse the stream instead of rejecting it.
	if
	(
		(
			header.flags.as_fields.sizing != IFF_Header_Sizing_32
			&& header.flags.as_fields.sizing != IFF_Header_Sizing_64
			&& header.flags.as_fields.sizing != IFF_Header_Sizing_16
		)
		|| header.flags.as_fields.tag_sizing > IFF_Header_TagSizing_16
		|| header.flags.as_fields.operating > IFF_Header_Operating_PROGRESSIVE
		|| header.flags.as_fields.encoding != IFF_Header_Encoding_BASE_256
		|| (
			header.flags.as_fields.typing
			& (VPS_TYPE_8U)~(IFF_Header_Flag_Typing_UNSIGNED_SIZES | IFF_Header_Flag_Typing_LITTLE_ENDIAN)
		)
		|| (
			header.flags.as_fields.structuring
			& (VPS_TYPE_8U)~(
				IFF_Header_Flag_Structuring_NO_PADDING
				| IFF_Header_Flag_Structuring_SHARDING
				| IFF_Header_Flag_Structuring_STRICT_CONTAINERS
			)
		)
		|| header.flags.as_fields.reserved != 0
	)
	{
		result->action = IFF_ACTION_HALT;
		result->payload.error_code = IFF_ERROR_UNSUPPORTED_FEATURE;
		return 1;
	}

	// --- Host Capability Check ---
	// Before applying the flags, check if the host can support the request.
	if (header.flags.as_fields.sizing == IFF_Header_Sizing_64 && sizeof(VPS_TYPE_SIZE) < 8)
	{
		// This is a 32-bit build, but the file is requesting 64-bit sizes.
		result->action = IFF_ACTION_HALT;
		result->payload.error_code = IFF_ERROR_UNSUPPORTED_FEATURE;
		return 1;
	}

	// The request is valid and supported.
	// Build the command to update the parser's active flags.
	result->action = IFF_ACTION_UPDATE_FLAGS;
	result->payload.new_flags = header.flags;

	return 1;
}
