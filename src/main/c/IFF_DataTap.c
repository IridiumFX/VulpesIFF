#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>

#include <IFF/IFF_DataPump.h>
#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_ChecksumCalculator.h>
#include <IFF/IFF_ChecksumSpan.h>
#include <IFF/IFF_DataTap.h>

/**
 * @brief Private helper to feed raw data to all active calculators.
 * @details This function iterates through every active span, and for each span,
 *          iterates through every active calculator, calling its `update` method.
 */
static void IFF_DataTap_PRIVATE_UpdateAllSpans
(
	struct IFF_DataTap* tap,
	const struct VPS_Data* raw_data
)
{
	struct VPS_List_Node* span_node = tap->active_spans->head;
	while (span_node)
	{
		struct IFF_ChecksumSpan* span = span_node->data;
		struct VPS_List_Node* calc_node = span->calculators->head;
		while (calc_node)
		{
			struct IFF_ChecksumCalculator* calc = calc_node->data;
			if (calc->algorithm && calc->algorithm->update)
			{
				calc->algorithm->update(calc->context, raw_data);
			}
			calc_node = calc_node->next;
		}
		span_node = span_node->next;
	}
}

char IFF_DataTap_Allocate
(
	struct IFF_DataTap **item
)
{
	struct IFF_DataTap* tap;

	if (!item)
	{
		return 0;
	}

	tap = calloc(1, sizeof(struct IFF_DataTap));
	if (!tap)
	{
		return 0;
	}

	if (!IFF_DataPump_Allocate(&tap->pump))
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

	IFF_DataTap_Release(tap);

	return 0;
}

char IFF_DataTap_Construct
(
	struct IFF_DataTap *item
	, int fh
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_DataPump_Construct(item->pump, fh)) return 0;

	// The dictionary keys are const char* identifiers, which we don't own.
	// The data are const IFF_ChecksumAlgorithm* pointers, which we also don't own.
	VPS_Dictionary_Construct(
		item->registered_algorithms,
		(char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_String,
		(char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_String,
		0, // No key_release
		0, // No data_release
		2, 75, 8
	);

	// The list owns the IFF_ChecksumSpan objects. When a node is removed/cleared,
	// it will call IFF_ChecksumSpan_Release on the data pointer.
	VPS_List_Construct(
		item->active_spans,
		0, 0,
		(char(*)(void*))IFF_ChecksumSpan_Release
	);

	return 1;
}

char IFF_DataTap_ConstructFromData
(
	struct IFF_DataTap *item
	, const struct VPS_Data *source
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_DataPump_ConstructFromData(item->pump, source)) return 0;

	VPS_Dictionary_Construct(
		item->registered_algorithms,
		(char(*)(void*, VPS_TYPE_SIZE*))VPS_Hash_Utils_String,
		(char(*)(void*, void*, VPS_TYPE_16S*))VPS_Compare_Utils_String,
		0, 0,
		2, 75, 8
	);

	VPS_List_Construct(
		item->active_spans,
		0, 0,
		(char(*)(void*))IFF_ChecksumSpan_Release
	);

	return 1;
}

char IFF_DataTap_Deconstruct
(
	struct IFF_DataTap *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Deconstruct(item->registered_algorithms);
	// Deconstructing the list will clear it, releasing all contained spans.
	VPS_List_Deconstruct(item->active_spans);

	IFF_DataPump_Deconstruct(item->pump);

	return 1;
}

char IFF_DataTap_Release
(
	struct IFF_DataTap *item
)
{
	if (item)
	{
		IFF_DataTap_Deconstruct(item);
		IFF_DataPump_Release(item->pump);
		VPS_Dictionary_Release(item->registered_algorithms);
		VPS_List_Release(item->active_spans);
		free(item);
	}
	return 1;
}

char IFF_DataTap_RegisterAlgorithm
(
	struct IFF_DataTap* tap,
	const struct IFF_ChecksumAlgorithm* algorithm
)
{
	if (!tap || !algorithm || !algorithm->identifier)
	{
		return 0;
	}

	// The dictionary does not take ownership of the key or data pointers.
	return VPS_Dictionary_Add(tap->registered_algorithms, (void*)algorithm->identifier, (void*)algorithm);
}

char IFF_DataTap_ReadRaw
(
	struct IFF_DataTap *tap
	, VPS_TYPE_SIZE bytes_to_read
	, struct VPS_Data **out_data
)
{
	if (!tap || !tap->pump)
	{
		return 0;
	}

	// 1. Call the underlying pump to get the raw bytes.
	if (!IFF_DataPump_ReadRaw(tap->pump, bytes_to_read, out_data))
	{
		return 0;
	}

	// 2. If the read was successful and there are active spans, update them.
	if (*out_data && tap->active_spans->count > 0)
	{
		IFF_DataTap_PRIVATE_UpdateAllSpans(tap, *out_data);
	}

	return 1;
}

char IFF_DataTap_StartSpan
(
	struct IFF_DataTap *tap
	, const struct VPS_Set *algorithm_identifiers
)
{
	struct IFF_ChecksumSpan* new_span = 0;
	struct VPS_List_Node* new_span_node = 0;

	if (!tap || !algorithm_identifiers) return 0;

	if (!IFF_ChecksumSpan_Allocate(&new_span) || !IFF_ChecksumSpan_Construct(new_span))
	{
		IFF_ChecksumSpan_Release(new_span);
		return 0;
	}

	// Iterate through all buckets of the set
	for (VPS_TYPE_SIZE i = 0; i < algorithm_identifiers->buckets; ++i)
	{
		struct VPS_List* bucket = algorithm_identifiers->bucket_vector[i];
		struct VPS_List_Node* set_entry_node = bucket->head;
		// Iterate through all entries in the bucket
		while (set_entry_node)
		{
			struct VPS_Set_Entry* set_entry = set_entry_node->data;
			struct VPS_Data* identifier_data = set_entry->item;
			const char* identifier = (const char*)identifier_data->bytes;

			struct IFF_ChecksumAlgorithm* algo = 0;
			if (VPS_Dictionary_Find(tap->registered_algorithms, (void*)identifier, (void**)&algo))
			{
				struct IFF_ChecksumCalculator* calc = 0;
				struct VPS_List_Node* calc_node = 0;
				if (IFF_ChecksumCalculator_Allocate(&calc) && IFF_ChecksumCalculator_Construct(calc, algo) && VPS_List_Node_Allocate(&calc_node))
				{
					VPS_List_Node_Construct(calc_node, calc);
					VPS_List_AddTail(new_span->calculators, calc_node);
				}
				else
				{
					// Cleanup on failure
					IFF_ChecksumCalculator_Release(calc);
					VPS_List_Node_Release(calc_node);
					IFF_ChecksumSpan_Release(new_span);
					return 0;
				}
			}
			set_entry_node = set_entry_node->next;
		}
	}

	// Add the fully populated span to the LIFO stack (head of the list)
	if (!VPS_List_Node_Allocate(&new_span_node)) { IFF_ChecksumSpan_Release(new_span); return 0; }
	VPS_List_Node_Construct(new_span_node, new_span);
	VPS_List_AddHead(tap->active_spans, new_span_node);

	return 1;
}

char IFF_DataTap_EndSpan
(
	struct IFF_DataTap *tap
	, struct VPS_Dictionary *expected_checksums
)
{
	struct VPS_List_Node* span_node = 0;
	struct IFF_ChecksumSpan* span = 0;
	char all_match = 1;

	if (!tap || !expected_checksums) return 0;

	// Pop the most recent span from the LIFO stack
	if (!VPS_List_RemoveHead(tap->active_spans, &span_node))
	{
		return 0;
	}
	span = span_node->data;

	struct VPS_List_Node* calc_node = span->calculators->head;
	while (calc_node)
	{
		struct IFF_ChecksumCalculator* calc = calc_node->data;
		struct VPS_Data* expected_data = 0;
		struct VPS_Data* calculated_data = 0;

		// Finalize the calculation
		if (!VPS_Data_Allocate(&calculated_data, 0, 0) || !calc->algorithm->finalize(calc->context, calculated_data))
		{
			all_match = 0;
			break;
		}

		// Find the expected value
		if (VPS_Dictionary_Find(expected_checksums, (void*)calc->algorithm->identifier, (void**)&expected_data))
		{
			VPS_TYPE_16S ordering;
			// Compare using VPS_Data's built-in comparison logic
			if (!VPS_Compare_Utils_Data(calculated_data, expected_data, &ordering) || ordering != 0)
			{
				all_match = 0;
			}
		}
		else
		{
			all_match = 0; // 'SUM' chunk was missing an expected value
		}

		VPS_Data_Release(calculated_data);
		if (!all_match) break;
		calc_node = calc_node->next;
	}

	// Cleanup the node and the span it contained
	IFF_ChecksumSpan_Release(span); // This releases the span and its internal list of calculators.
	VPS_List_Node_Release(span_node); // This just releases the list node container.

	return all_match;
}

char IFF_DataTap_Skip
(
	struct IFF_DataTap *tap
	, VPS_TYPE_SIZE bytes_to_skip
)
{
	struct VPS_Data *skipped_data = 0;

	if (!tap)
	{
		return 0;
	}

	if (tap->active_spans->count > 0)
	{
		if (!IFF_DataTap_ReadRaw(tap, bytes_to_skip, &skipped_data))
		{
			return 0;
		}

		// We read data just to checksum it. Release it again
		VPS_Data_Release(skipped_data);

		return 1;
	}

	return IFF_DataPump_Skip
	(
		tap->pump
		, bytes_to_skip
	);
}

