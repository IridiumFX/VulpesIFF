#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataWriter.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_WriteScope.h>

IFF_TYPE_RESULT IFF_WriteScope_Allocate
(
	struct IFF_WriteScope **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_WriteScope));

	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WriteScope_Construct
(
	struct IFF_WriteScope *item
	, union IFF_Header_Flags flags
	, struct IFF_Tag variant
	, struct IFF_Tag type
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->flags = flags;
	item->container_variant = variant;
	item->container_type = type;
	item->accumulator = 0;
	item->accumulator_writer = 0;
	item->form_encoder = 0;
	item->form_state = 0;
	item->bytes_written = 0;

	/* In blobbed mode, allocate an accumulator buffer */
	if (flags.as_fields.operating == IFF_Header_Operating_BLOBBED)
	{
		if (VPS_Data_Allocate(&item->accumulator, 256, 0))
		{
			return IFF_FAIL;
		}

		if (VPS_Data_Construct(item->accumulator))
		{
			VPS_Data_Release(item->accumulator);
			item->accumulator = 0;
			return IFF_FAIL;
		}

		if (VPS_DataWriter_Allocate(&item->accumulator_writer))
		{
			VPS_Data_Release(item->accumulator);
			item->accumulator = 0;
			return IFF_FAIL;
		}

		if (VPS_DataWriter_Construct(item->accumulator_writer, item->accumulator))
		{
			VPS_DataWriter_Release(item->accumulator_writer);
			item->accumulator_writer = 0;
			VPS_Data_Release(item->accumulator);
			item->accumulator = 0;
			return IFF_FAIL;
		}
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WriteScope_Deconstruct
(
	struct IFF_WriteScope *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->form_encoder = 0;
	item->form_state = 0;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WriteScope_Release
(
	struct IFF_WriteScope *item
)
{
	if (item)
	{
		IFF_WriteScope_Deconstruct(item);
		VPS_DataWriter_Release(item->accumulator_writer);
		VPS_Data_Release(item->accumulator);
		free(item);
	}

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

VPS_TYPE_RESULT IFF_WriteScope_VPS_Release
(
	void *item
)
{
	return IFF_WriteScope_Release(item);
}
