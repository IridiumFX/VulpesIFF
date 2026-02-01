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
