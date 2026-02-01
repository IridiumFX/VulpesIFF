#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>

#include <IFF/IFF_WritePump.h>
#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_ChecksumCalculator.h>
#include <IFF/IFF_ChecksumSpan.h>
#include <IFF/IFF_WriteTap.h>

/**
 * @brief Private helper to feed raw data to all active calculators.
 */
static void IFF_WriteTap_PRIVATE_UpdateAllSpans
(
	struct IFF_WriteTap *tap
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	struct VPS_Data wrapper;
	struct VPS_List_Node *span_node;

	wrapper.bytes = (unsigned char *)data;
	wrapper.size = size;
	wrapper.position = 0;
	wrapper.limit = size;
	wrapper.own_bytes = 0;

	span_node = tap->active_spans->head;
	while (span_node)
	{
		struct IFF_ChecksumSpan *span = span_node->data;
		struct VPS_List_Node *calc_node = span->calculators->head;
		while (calc_node)
		{
			struct IFF_ChecksumCalculator *calc = calc_node->data;
			if (calc->algorithm && calc->algorithm->update)
			{
				calc->algorithm->update(calc->context, &wrapper);
			}
			calc_node = calc_node->next;
		}
		span_node = span_node->next;
	}
}

char IFF_WriteTap_Allocate
(
	struct IFF_WriteTap **item
)
{
	struct IFF_WriteTap *tap;

	if (!item)
	{
		return 0;
	}

	tap = calloc(1, sizeof(struct IFF_WriteTap));
	if (!tap)
	{
		return 0;
	}

	if (!IFF_WritePump_Allocate(&tap->pump))
	{
		goto cleanup;
	}

	if (!VPS_Dictionary_Allocate(&tap->registered_algorithms, 17))
	{
		goto cleanup;
	}

	if (!VPS_List_Allocate(&tap->active_spans))
	{
		goto cleanup;
	}

	*item = tap;

	return 1;

cleanup:

	IFF_WriteTap_Release(tap);

	return 0;
}

char IFF_WriteTap_Construct
(
	struct IFF_WriteTap *item
	, int file_handle
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_WritePump_Construct(item->pump, file_handle))
	{
		return 0;
	}

	VPS_Dictionary_Construct
	(
		item->registered_algorithms
		, (char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_String
		, (char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_String
		, 0
		, 0
		, 2, 75, 8
	);

	VPS_List_Construct
	(
		item->active_spans
		, 0, 0
		, (char(*)(void*))IFF_ChecksumSpan_Release
	);

	return 1;
}

char IFF_WriteTap_ConstructToData
(
	struct IFF_WriteTap *item
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_WritePump_ConstructToData(item->pump))
	{
		return 0;
	}

	VPS_Dictionary_Construct
	(
		item->registered_algorithms
		, (char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_String
		, (char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_String
		, 0
		, 0
		, 2, 75, 8
	);

	VPS_List_Construct
	(
		item->active_spans
		, 0, 0
		, (char(*)(void*))IFF_ChecksumSpan_Release
	);

	return 1;
}

char IFF_WriteTap_GetOutputData
(
	struct IFF_WriteTap *tap
	, struct VPS_Data **out_data
)
{
	if (!tap)
	{
		return 0;
	}

	return IFF_WritePump_GetOutputData(tap->pump, out_data);
}

char IFF_WriteTap_Deconstruct
(
	struct IFF_WriteTap *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Deconstruct(item->registered_algorithms);
	VPS_List_Deconstruct(item->active_spans);
	IFF_WritePump_Deconstruct(item->pump);

	return 1;
}

char IFF_WriteTap_Release
(
	struct IFF_WriteTap *item
)
{
	if (item)
	{
		IFF_WriteTap_Deconstruct(item);
		IFF_WritePump_Release(item->pump);
		VPS_Dictionary_Release(item->registered_algorithms);
		VPS_List_Release(item->active_spans);
		free(item);
	}

	return 1;
}

char IFF_WriteTap_RegisterAlgorithm
(
	struct IFF_WriteTap *tap
	, const struct IFF_ChecksumAlgorithm *algorithm
)
{
	if (!tap || !algorithm || !algorithm->identifier)
	{
		return 0;
	}

	return VPS_Dictionary_Add(tap->registered_algorithms, (void *)algorithm->identifier, (void *)algorithm);
}

char IFF_WriteTap_WriteRaw
(
	struct IFF_WriteTap *tap
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	if (!tap || (!data && size > 0))
	{
		return 0;
	}

	if (tap->active_spans->count > 0)
	{
		IFF_WriteTap_PRIVATE_UpdateAllSpans(tap, data, size);
	}

	return IFF_WritePump_WriteRaw(tap->pump, data, size);
}

char IFF_WriteTap_WriteData
(
	struct IFF_WriteTap *tap
	, const struct VPS_Data *data
)
{
	if (!tap || !data)
	{
		return 0;
	}

	return IFF_WriteTap_WriteRaw(tap, data->bytes, data->limit);
}

char IFF_WriteTap_StartSpan
(
	struct IFF_WriteTap *tap
	, const struct VPS_Set *algorithm_identifiers
)
{
	struct IFF_ChecksumSpan *new_span = 0;
	struct VPS_List_Node *new_span_node = 0;
	VPS_TYPE_SIZE i;

	if (!tap || !algorithm_identifiers)
	{
		return 0;
	}

	if (!IFF_ChecksumSpan_Allocate(&new_span) || !IFF_ChecksumSpan_Construct(new_span))
	{
		IFF_ChecksumSpan_Release(new_span);
		return 0;
	}

	for (i = 0; i < algorithm_identifiers->buckets; ++i)
	{
		struct VPS_List *bucket = algorithm_identifiers->bucket_vector[i];
		struct VPS_List_Node *set_entry_node = bucket->head;

		while (set_entry_node)
		{
			struct VPS_Set_Entry *set_entry = set_entry_node->data;
			struct VPS_Data *identifier_data = set_entry->item;
			const char *identifier = (const char *)identifier_data->bytes;

			struct IFF_ChecksumAlgorithm *algo = 0;
			if (VPS_Dictionary_Find(tap->registered_algorithms, (void *)identifier, (void **)&algo))
			{
				struct IFF_ChecksumCalculator *calc = 0;
				struct VPS_List_Node *calc_node = 0;

				if
				(
					IFF_ChecksumCalculator_Allocate(&calc)
					&& IFF_ChecksumCalculator_Construct(calc, algo)
					&& VPS_List_Node_Allocate(&calc_node)
				)
				{
					VPS_List_Node_Construct(calc_node, calc);
					VPS_List_AddTail(new_span->calculators, calc_node);
				}
				else
				{
					IFF_ChecksumCalculator_Release(calc);
					VPS_List_Node_Release(calc_node);
					IFF_ChecksumSpan_Release(new_span);
					return 0;
				}
			}
			set_entry_node = set_entry_node->next;
		}
	}

	if (!VPS_List_Node_Allocate(&new_span_node))
	{
		IFF_ChecksumSpan_Release(new_span);
		return 0;
	}

	VPS_List_Node_Construct(new_span_node, new_span);
	VPS_List_AddHead(tap->active_spans, new_span_node);

	return 1;
}

char IFF_WriteTap_EndSpan
(
	struct IFF_WriteTap *tap
	, struct VPS_Dictionary **out_checksums
)
{
	struct VPS_List_Node *span_node = 0;
	struct IFF_ChecksumSpan *span = 0;
	struct VPS_Dictionary *checksums = 0;

	if (!tap || !out_checksums)
	{
		return 0;
	}

	if (!VPS_List_RemoveHead(tap->active_spans, &span_node))
	{
		return 0;
	}

	span = span_node->data;

	if (!VPS_Dictionary_Allocate(&checksums, 7))
	{
		IFF_ChecksumSpan_Release(span);
		VPS_List_Node_Release(span_node);
		return 0;
	}

	VPS_Dictionary_Construct
	(
		checksums
		, (char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_String
		, (char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_String
		, 0
		, (char(*)(void*))VPS_Data_Release
		, 2, 75, 8
	);

	{
		struct VPS_List_Node *calc_node = span->calculators->head;
		while (calc_node)
		{
			struct IFF_ChecksumCalculator *calc = calc_node->data;
			struct VPS_Data *calculated_data = 0;

			if
			(
				!VPS_Data_Allocate(&calculated_data, 0, 0)
				|| !calc->algorithm->finalize(calc->context, calculated_data)
			)
			{
				VPS_Data_Release(calculated_data);
				VPS_Dictionary_Release(checksums);
				IFF_ChecksumSpan_Release(span);
				VPS_List_Node_Release(span_node);
				return 0;
			}

			if (!VPS_Dictionary_Add(checksums, (void *)calc->algorithm->identifier, calculated_data))
			{
				VPS_Data_Release(calculated_data);
				VPS_Dictionary_Release(checksums);
				IFF_ChecksumSpan_Release(span);
				VPS_List_Node_Release(span_node);
				return 0;
			}

			calc_node = calc_node->next;
		}
	}

	*out_checksums = checksums;

	IFF_ChecksumSpan_Release(span);
	VPS_List_Node_Release(span_node);

	return 1;
}

char IFF_WriteTap_Flush
(
	struct IFF_WriteTap *tap
)
{
	if (!tap)
	{
		return 0;
	}

	return IFF_WritePump_Flush(tap->pump);
}
