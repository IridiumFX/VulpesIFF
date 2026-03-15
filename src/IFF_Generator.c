#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataWriter.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Endian.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_ChecksumCalculator.h>
#include <IFF/IFF_ChecksumSpan.h>
#include <IFF/IFF_WritePump.h>
#include <IFF/IFF_WriteTap.h>
#include <IFF/IFF_Writer.h>
#include <IFF/IFF_WriteScope.h>
#include <IFF/IFF_Generator_State.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_Generator.h>

/* ------------------------------------------------------------------ */
/*  Private: blobbed checksum span tracking                            */
/* ------------------------------------------------------------------ */

struct IFF_WriteBlobbedSpan
{
	struct VPS_Data *accumulator;       /* borrowed ref to scope's accumulator */
	VPS_TYPE_SIZE start_offset;         /* accumulator->limit at span start */
	struct IFF_ChecksumSpan *span;      /* owns the calculators */
};

static char PRIVATE_IFF_Generator_ReleaseBlobbedSpan
(
	void *ptr
)
{
	struct IFF_WriteBlobbedSpan *bs = ptr;

	if (bs)
	{
		IFF_ChecksumSpan_Release(bs->span);
		free(bs);
	}

	return 1;
}

static char PRIVATE_IFF_Generator_BeginBlobbedSpan
(
	struct IFF_Generator *gen
	, const struct VPS_Set *algorithm_ids
)
{
	struct IFF_WriteScope *scope;
	struct IFF_ChecksumSpan *new_span = 0;
	struct IFF_WriteBlobbedSpan *bs = 0;
	struct VPS_List_Node *bs_node = 0;
	VPS_TYPE_SIZE i;

	scope = gen->scope_stack->tail ? gen->scope_stack->tail->data : 0;
	if (!scope || !scope->accumulator)
	{
		return 0;
	}

	/* Create a ChecksumSpan with calculators from registered algorithms */
	if (!IFF_ChecksumSpan_Allocate(&new_span) || !IFF_ChecksumSpan_Construct(new_span))
	{
		IFF_ChecksumSpan_Release(new_span);
		return 0;
	}

	for (i = 0; i < algorithm_ids->buckets; ++i)
	{
		struct VPS_List *bucket = algorithm_ids->bucket_vector[i];
		struct VPS_List_Node *set_entry_node = bucket->head;

		while (set_entry_node)
		{
			struct VPS_Set_Entry *set_entry = set_entry_node->data;
			struct VPS_Data *identifier_data = set_entry->item;
			const char *identifier = (const char *)identifier_data->bytes;

			struct IFF_ChecksumAlgorithm *algo = 0;
			if (VPS_Dictionary_Find(gen->writer->tap->registered_algorithms, (void *)identifier, (void **)&algo))
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

	/* Create the blobbed span record */
	bs = calloc(1, sizeof(struct IFF_WriteBlobbedSpan));
	if (!bs)
	{
		IFF_ChecksumSpan_Release(new_span);
		return 0;
	}

	bs->accumulator = scope->accumulator;
	bs->start_offset = scope->accumulator->limit;
	bs->span = new_span;

	/* Push onto LIFO stack */
	if (!VPS_List_Node_Allocate(&bs_node))
	{
		PRIVATE_IFF_Generator_ReleaseBlobbedSpan(bs);
		return 0;
	}

	VPS_List_Node_Construct(bs_node, bs);
	VPS_List_AddHead(gen->blobbed_spans, bs_node);

	return 1;
}

static char PRIVATE_IFF_Generator_EndBlobbedSpan
(
	struct IFF_Generator *gen
	, struct VPS_Dictionary **out_checksums
)
{
	struct VPS_List_Node *bs_node = 0;
	struct IFF_WriteBlobbedSpan *bs = 0;
	struct VPS_Dictionary *checksums = 0;
	VPS_TYPE_SIZE span_size;

	if (!gen || !out_checksums)
	{
		return 0;
	}

	/* Pop the most recent blobbed span */
	if (!VPS_List_RemoveHead(gen->blobbed_spans, &bs_node))
	{
		return 0;
	}

	bs = bs_node->data;

	/* Feed the accumulated bytes to calculators */
	span_size = bs->accumulator->limit - bs->start_offset;

	if (span_size > 0)
	{
		struct VPS_Data wrapper;
		struct VPS_List_Node *calc_node;

		wrapper.bytes = bs->accumulator->bytes + bs->start_offset;
		wrapper.size = span_size;
		wrapper.position = 0;
		wrapper.limit = span_size;
		wrapper.own_bytes = 0;

		calc_node = bs->span->calculators->head;
		while (calc_node)
		{
			struct IFF_ChecksumCalculator *calc = calc_node->data;
			if (calc->algorithm && calc->algorithm->update)
			{
				calc->algorithm->update(calc->context, &wrapper);
			}
			calc_node = calc_node->next;
		}
	}

	/*
	 * Also feed the SUM tag bytes to calculators. When the parser reads the
	 * stream, the content loop's ReadTag consumes the SUM tag through the
	 * DataTap before Parse_Directive handles it, so those tag bytes are
	 * included in the parser's checksum. We include them here too so both
	 * sides agree on which bytes are checksummed.
	 */
	{
		VPS_TYPE_8U tag_length = IFF_Header_Flags_GetTagLength(gen->flags.as_fields.tag_sizing);

		if (tag_length > 0)
		{
			unsigned char sum_tag_buf[IFF_TAG_CANONICAL_SIZE];
			struct VPS_Data sum_tag_wrapper;
			struct VPS_List_Node *stc;

			memcpy(sum_tag_buf, IFF_TAG_SYSTEM_SUM.data + (IFF_TAG_CANONICAL_SIZE - tag_length), tag_length);
			memset(&sum_tag_wrapper, 0, sizeof(sum_tag_wrapper));
			sum_tag_wrapper.bytes = sum_tag_buf;
			sum_tag_wrapper.size = tag_length;
			sum_tag_wrapper.limit = tag_length;

			stc = bs->span->calculators->head;
			while (stc)
			{
				struct IFF_ChecksumCalculator *calc = stc->data;
				if (calc->algorithm && calc->algorithm->update)
				{
					calc->algorithm->update(calc->context, &sum_tag_wrapper);
				}
				stc = stc->next;
			}
		}
	}

	/* Finalize calculators into output dictionary */
	if (!VPS_Dictionary_Allocate(&checksums, 7))
	{
		goto failure;
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
		struct VPS_List_Node *calc_node = bs->span->calculators->head;
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
				goto failure;
			}

			if (!VPS_Dictionary_Add(checksums, (void *)calc->algorithm->identifier, calculated_data))
			{
				VPS_Data_Release(calculated_data);
				goto failure;
			}

			calc_node = calc_node->next;
		}
	}

	*out_checksums = checksums;

	PRIVATE_IFF_Generator_ReleaseBlobbedSpan(bs);
	VPS_List_Node_Release(bs_node);

	return 1;

failure:

	VPS_Dictionary_Release(checksums);
	PRIVATE_IFF_Generator_ReleaseBlobbedSpan(bs);
	VPS_List_Node_Release(bs_node);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Private Helpers: write IFF primitives to a VPS_DataWriter buffer  */
/* ------------------------------------------------------------------ */

static char PRIVATE_IFF_Generator_WriteTagTo
(
	struct VPS_DataWriter *dw
	, enum IFF_Header_TagSizing tag_sizing
	, const struct IFF_Tag *tag
)
{
	VPS_TYPE_8U tag_length = IFF_Header_Flags_GetTagLength(tag_sizing);

	if (tag_length == 0)
	{
		return 0;
	}

	if (tag->type == IFF_TAG_TYPE_DIRECTIVE)
	{
		return VPS_DataWriter_WriteBytes(dw, tag->data + (IFF_TAG_CANONICAL_SIZE - tag_length), tag_length);
	}
	else
	{
		return VPS_DataWriter_WriteBytes(dw, tag->data, tag_length);
	}
}

static char PRIVATE_IFF_Generator_WriteSizeTo
(
	struct VPS_DataWriter *dw
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_SIZE size
)
{
	unsigned char buf[8];
	VPS_TYPE_8U size_length = IFF_Header_Flags_GetSizeLength(sizing);
	char is_le = typing & IFF_Header_Flag_Typing_LITTLE_ENDIAN;

	if (size_length == 0)
	{
		return 0;
	}

	switch (sizing)
	{
		case IFF_Header_Sizing_16:
			if (is_le) VPS_Endian_Write16ULE(buf, (VPS_TYPE_16U)size);
			else       VPS_Endian_Write16UBE(buf, (VPS_TYPE_16U)size);
			break;

		case IFF_Header_Sizing_64:
			if (is_le) VPS_Endian_Write64ULE(buf, (VPS_TYPE_64U)size);
			else       VPS_Endian_Write64UBE(buf, (VPS_TYPE_64U)size);
			break;

		default: /* IFF_Header_Sizing_32 */
			if (is_le) VPS_Endian_Write32ULE(buf, (VPS_TYPE_32U)size);
			else       VPS_Endian_Write32UBE(buf, (VPS_TYPE_32U)size);
	}

	return VPS_DataWriter_WriteBytes(dw, buf, size_length);
}

static char PRIVATE_IFF_Generator_WriteDataTo
(
	struct VPS_DataWriter *dw
	, const struct VPS_Data *data
)
{
	if (!data || data->limit == 0)
	{
		return 1;
	}

	return VPS_DataWriter_WriteBytes(dw, data->bytes, data->limit);
}

static char PRIVATE_IFF_Generator_WritePaddingTo
(
	struct VPS_DataWriter *dw
	, const struct IFF_Header_Flags_Fields *config
	, VPS_TYPE_SIZE data_size
)
{
	if (config->structuring & IFF_Header_Flag_Structuring_NO_PADDING)
	{
		return 1;
	}

	if (data_size & 1)
	{
		return VPS_DataWriter_Write8U(dw, 0);
	}

	return 1;
}

static VPS_TYPE_SIZE PRIVATE_IFF_Generator_PaddingSize
(
	const struct IFF_Header_Flags_Fields *config
	, VPS_TYPE_SIZE data_size
)
{
	if (config->structuring & IFF_Header_Flag_Structuring_NO_PADDING)
	{
		return 0;
	}

	return (data_size & 1) ? 1 : 0;
}

static char PRIVATE_IFF_Generator_WriteChunkTo
(
	struct VPS_DataWriter *dw
	, const struct IFF_Header_Flags_Fields *config
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
)
{
	VPS_TYPE_SIZE data_size = data ? data->limit : 0;

	if (!PRIVATE_IFF_Generator_WriteTagTo(dw, config->tag_sizing, tag))
	{
		return 0;
	}

	if (!PRIVATE_IFF_Generator_WriteSizeTo(dw, config->sizing, config->typing, data_size))
	{
		return 0;
	}

	if (data_size > 0)
	{
		if (!PRIVATE_IFF_Generator_WriteDataTo(dw, data))
		{
			return 0;
		}
	}

	return 1;
}

/* ------------------------------------------------------------------ */
/*  Current scope helpers                                              */
/* ------------------------------------------------------------------ */

static struct IFF_WriteScope* PRIVATE_IFF_Generator_CurrentScope
(
	struct IFF_Generator *gen
)
{
	if (!gen->scope_stack || gen->scope_stack->count == 0)
	{
		return 0;
	}

	return gen->scope_stack->tail->data;
}

static char PRIVATE_IFF_Generator_IsBlobbed
(
	struct IFF_Generator *gen
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope)
	{
		return scope->flags.as_fields.operating == IFF_Header_Operating_BLOBBED;
	}

	return gen->flags.as_fields.operating == IFF_Header_Operating_BLOBBED;
}

/* ------------------------------------------------------------------ */
/*  Content-type validation helpers                                    */
/* ------------------------------------------------------------------ */

static char PRIVATE_IFF_Generator_IsVariant
(
	const struct IFF_Tag *a
	, const struct IFF_Tag *b
)
{
	VPS_TYPE_16S ordering;

	if (!IFF_Tag_Compare(a, b, &ordering))
	{
		return 0;
	}

	return ordering == 0;
}

/**
 * @brief Validates that a data chunk is allowed in the current scope.
 * @details Chunks are only allowed inside FORM and PROP containers.
 */
static char PRIVATE_IFF_Generator_ValidateChunkAllowed
(
	struct IFF_Generator *gen
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (!scope)
	{
		/* No container — chunks not allowed at top level */
		return 0;
	}

	/* FORM and PROP accept chunks */
	if (PRIVATE_IFF_Generator_IsVariant(&scope->container_variant, &IFF_TAG_SYSTEM_FORM))
	{
		return 1;
	}

	if (PRIVATE_IFF_Generator_IsVariant(&scope->container_variant, &IFF_TAG_SYSTEM_PROP))
	{
		return 1;
	}

	/* LIST and CAT do not accept chunks */
	return 0;
}

/**
 * @brief Validates that a container (FORM/LIST/CAT/PROP) is allowed in the current scope.
 * @details At top-level: any container is allowed.
 *          Inside FORM/PROP: no nested containers allowed.
 *          Inside LIST: FORM, LIST, CAT, and PROP are allowed.
 *          Inside CAT: FORM, LIST, CAT are allowed; PROP is not.
 *          When STRICT_CONTAINERS is set and the parent is CAT or LIST with
 *          a non-wildcard type, the child's type must match.
 */
static char PRIVATE_IFF_Generator_ValidateContainerAllowed
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *variant
	, const struct IFF_Tag *type
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (!scope)
	{
		/* Top-level: FORM, LIST, CAT allowed. PROP only valid inside LIST. */
		if (PRIVATE_IFF_Generator_IsVariant(variant, &IFF_TAG_SYSTEM_PROP))
		{
			return 0;
		}
		return 1;
	}

	/* FORM allows nested containers (FORM, LIST, CAT) but not PROP */
	if (PRIVATE_IFF_Generator_IsVariant(&scope->container_variant, &IFF_TAG_SYSTEM_FORM))
	{
		if (PRIVATE_IFF_Generator_IsVariant(variant, &IFF_TAG_SYSTEM_PROP))
		{
			return 0;
		}
		goto strict_check;
	}

	/* PROP does not allow nested containers */
	if (PRIVATE_IFF_Generator_IsVariant(&scope->container_variant, &IFF_TAG_SYSTEM_PROP))
	{
		return 0;
	}

	/* LIST allows FORM, LIST, CAT, and PROP */
	if (PRIVATE_IFF_Generator_IsVariant(&scope->container_variant, &IFF_TAG_SYSTEM_LIST))
	{
		goto strict_check;
	}

	/* CAT allows FORM, LIST, CAT but not PROP */
	if (PRIVATE_IFF_Generator_IsVariant(&scope->container_variant, &IFF_TAG_SYSTEM_CAT))
	{
		if (PRIVATE_IFF_Generator_IsVariant(variant, &IFF_TAG_SYSTEM_PROP))
		{
			return 0;
		}

		goto strict_check;
	}

	return 0;

strict_check:

	/* STRICT_CONTAINERS: child type must match parent's declared type
	 * (unless parent has wildcard type) */
	if (gen->flags.as_fields.structuring & IFF_Header_Flag_Structuring_STRICT_CONTAINERS)
	{
		if (!PRIVATE_IFF_Generator_IsVariant(&scope->container_type, &IFF_TAG_SYSTEM_WILDCARD))
		{
			if (!PRIVATE_IFF_Generator_IsVariant(type, &scope->container_type))
			{
				return 0;
			}
		}
	}

	return 1;
}

/* ------------------------------------------------------------------ */
/*  Unified write helpers that dispatch to stream or accumulator       */
/* ------------------------------------------------------------------ */

static char PRIVATE_IFF_Generator_EmitTag
(
	struct IFF_Generator *gen
	, enum IFF_Header_TagSizing tag_sizing
	, const struct IFF_Tag *tag
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope && scope->accumulator_writer)
	{
		return PRIVATE_IFF_Generator_WriteTagTo(scope->accumulator_writer, tag_sizing, tag);
	}

	return IFF_Writer_WriteTag(gen->writer, tag_sizing, tag);
}

static char PRIVATE_IFF_Generator_EmitSize
(
	struct IFF_Generator *gen
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_SIZE size
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope && scope->accumulator_writer)
	{
		return PRIVATE_IFF_Generator_WriteSizeTo(scope->accumulator_writer, sizing, typing, size);
	}

	return IFF_Writer_WriteSize(gen->writer, sizing, typing, size);
}

static char PRIVATE_IFF_Generator_EmitData
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope && scope->accumulator_writer)
	{
		return PRIVATE_IFF_Generator_WriteDataTo(scope->accumulator_writer, data);
	}

	return IFF_Writer_WriteData(gen->writer, IFF_Header_Encoding_BASE_256, data);
}

static char PRIVATE_IFF_Generator_EmitRaw
(
	struct IFF_Generator *gen
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope && scope->accumulator_writer)
	{
		return VPS_DataWriter_WriteBytes(scope->accumulator_writer, data, size);
	}

	return IFF_WriteTap_WriteRaw(gen->writer->tap, data, size);
}

static char PRIVATE_IFF_Generator_EmitPadding
(
	struct IFF_Generator *gen
	, const struct IFF_Header_Flags_Fields *config
	, VPS_TYPE_SIZE data_size
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope && scope->accumulator_writer)
	{
		return PRIVATE_IFF_Generator_WritePaddingTo(scope->accumulator_writer, config, data_size);
	}

	return IFF_Writer_WritePadding(gen->writer, config, data_size);
}

static char PRIVATE_IFF_Generator_EmitChunk
(
	struct IFF_Generator *gen
	, const struct IFF_Header_Flags_Fields *config
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
)
{
	struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);

	if (scope && scope->accumulator_writer)
	{
		return PRIVATE_IFF_Generator_WriteChunkTo(scope->accumulator_writer, config, tag, data);
	}

	return IFF_Writer_WriteChunk(gen->writer, config, tag, data);
}

/* ------------------------------------------------------------------ */
/*  Tracked chunk emission (tag + size + data + padding + tracking)    */
/* ------------------------------------------------------------------ */

/**
 * @brief Emits a complete chunk (tag + size + data + padding) and tracks
 *        bytes_written on the current scope.
 * @details Used by WriteChunk, WriteDEF, WriteREF, BeginChecksumSpan,
 *          EndChecksumSpan, and WriteFiller.
 */
static char PRIVATE_IFF_Generator_EmitTrackedChunk
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
)
{
	const struct IFF_Header_Flags_Fields *config = &gen->flags.as_fields;
	VPS_TYPE_SIZE data_size = data ? data->limit : 0;

	if (!PRIVATE_IFF_Generator_EmitChunk(gen, config, tag, data))
	{
		return 0;
	}

	if (!PRIVATE_IFF_Generator_EmitPadding(gen, config, data_size))
	{
		return 0;
	}

	/* Track bytes on current scope */
	{
		struct IFF_WriteScope *scope = PRIVATE_IFF_Generator_CurrentScope(gen);
		if (scope)
		{
			VPS_TYPE_SIZE tag_len = IFF_Header_Flags_GetTagLength(config->tag_sizing);
			VPS_TYPE_SIZE size_len = IFF_Header_Flags_GetSizeLength(config->sizing);
			VPS_TYPE_SIZE padding = PRIVATE_IFF_Generator_PaddingSize(config, data_size);
			scope->bytes_written += tag_len + size_len + data_size + padding;
		}
	}

	return 1;
}

/* ------------------------------------------------------------------ */
/*  Container begin/end helpers                                        */
/* ------------------------------------------------------------------ */

static char PRIVATE_IFF_Generator_BeginContainer
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *variant
	, const struct IFF_Tag *type
)
{
	struct IFF_WriteScope *new_scope = 0;
	struct VPS_List_Node *node = 0;
	const struct IFF_Header_Flags_Fields *config = &gen->flags.as_fields;

	if (!gen || !variant || !type)
	{
		return 0;
	}

	/* Validate: containers must be allowed in the current scope */
	if (!PRIVATE_IFF_Generator_ValidateContainerAllowed(gen, variant, type))
	{
		return 0;
	}

	/* Allocate and construct the new scope */
	if (!IFF_WriteScope_Allocate(&new_scope))
	{
		return 0;
	}

	if (!IFF_WriteScope_Construct(new_scope, gen->flags, *variant, *type))
	{
		IFF_WriteScope_Release(new_scope);
		return 0;
	}

	/* Prepare the list node (but don't push yet — write tags first) */
	if (!VPS_List_Node_Allocate(&node))
	{
		IFF_WriteScope_Release(new_scope);
		return 0;
	}

	VPS_List_Node_Construct(node, new_scope);

	/*
	 * IFF container structure: TAG SIZE TYPE [contents...]
	 * TYPE is part of the content bytes counted by SIZE.
	 *
	 * Progressive: write TAG + TYPE directly to stream (no SIZE; END-terminated).
	 * Blobbed: accumulator captures TYPE + contents.
	 *          On EndContainer we write TAG + SIZE(accumulator.limit) + accumulator.
	 *
	 * Write tags BEFORE pushing the scope so a failure doesn't orphan it.
	 */

	if (config->operating == IFF_Header_Operating_PROGRESSIVE)
	{
		if (!IFF_Writer_WriteTag(gen->writer, config->tag_sizing, variant))
		{
			goto begin_failure;
		}

		if (!IFF_Writer_WriteTag(gen->writer, config->tag_sizing, type))
		{
			goto begin_failure;
		}
	}
	else
	{
		/* Blobbed: write type tag into this scope's accumulator. */
		if (!PRIVATE_IFF_Generator_WriteTagTo(new_scope->accumulator_writer, config->tag_sizing, type))
		{
			goto begin_failure;
		}
	}

	/* Tags written successfully — now commit the scope */
	VPS_List_AddTail(gen->scope_stack, node);

	return 1;

begin_failure:

	IFF_WriteScope_Release(new_scope);
	VPS_List_Node_Release(node);

	return 0;
}

static char PRIVATE_IFF_Generator_EndContainer
(
	struct IFF_Generator *gen
)
{
	struct VPS_List_Node *node = 0;
	struct IFF_WriteScope *scope = 0;
	const struct IFF_Header_Flags_Fields *config;

	if (!gen || gen->scope_stack->count == 0)
	{
		return 0;
	}

	/* Pop the current scope */
	if (!VPS_List_RemoveTail(gen->scope_stack, &node))
	{
		return 0;
	}

	scope = node->data;
	config = &scope->flags.as_fields;

	if (config->operating == IFF_Header_Operating_PROGRESSIVE)
	{
		/* Write END directive: tag + size=0 */
		if (!IFF_Writer_WriteTag(gen->writer, config->tag_sizing, &IFF_TAG_SYSTEM_END))
		{
			goto failure;
		}

		if (!IFF_Writer_WriteSize(gen->writer, config->sizing, config->typing, 0))
		{
			goto failure;
		}

		/* Track bytes on parent: container tag + type tag + END tag + END size */
		{
			struct IFF_WriteScope *parent = PRIVATE_IFF_Generator_CurrentScope(gen);
			if (parent)
			{
				VPS_TYPE_SIZE tag_len = IFF_Header_Flags_GetTagLength(config->tag_sizing);
				VPS_TYPE_SIZE size_len = IFF_Header_Flags_GetSizeLength(config->sizing);
				parent->bytes_written += tag_len + tag_len + scope->bytes_written + tag_len + size_len;
			}
		}
	}
	else
	{
		/* Blobbed mode: write the complete container to the parent's target.
		 * Container format: TAG SIZE BODY
		 * where BODY = accumulator contents (starts with TYPE tag)
		 */
		VPS_TYPE_SIZE body_size = scope->accumulator->limit;
		VPS_TYPE_SIZE tag_len = IFF_Header_Flags_GetTagLength(config->tag_sizing);
		VPS_TYPE_SIZE size_len = IFF_Header_Flags_GetSizeLength(config->sizing);
		VPS_TYPE_SIZE padding = PRIVATE_IFF_Generator_PaddingSize(config, body_size);

		/* Determine the parent output target */
		struct IFF_WriteScope *parent = PRIVATE_IFF_Generator_CurrentScope(gen);

		if (parent && parent->accumulator_writer)
		{
			/* Parent is also blobbed: append to parent's accumulator */
			if (!PRIVATE_IFF_Generator_WriteTagTo(parent->accumulator_writer, config->tag_sizing, &scope->container_variant))
			{
				goto failure;
			}

			if (!PRIVATE_IFF_Generator_WriteSizeTo(parent->accumulator_writer, config->sizing, config->typing, body_size))
			{
				goto failure;
			}

			if (!VPS_DataWriter_WriteBytes(parent->accumulator_writer, scope->accumulator->bytes, body_size))
			{
				goto failure;
			}

			if (!PRIVATE_IFF_Generator_WritePaddingTo(parent->accumulator_writer, config, body_size))
			{
				goto failure;
			}

			/* Track bytes on parent */
			parent->bytes_written += tag_len + size_len + body_size + padding;
		}
		else
		{
			/* Root-level blobbed container: write to the actual writer */
			if (!IFF_Writer_WriteTag(gen->writer, config->tag_sizing, &scope->container_variant))
			{
				goto failure;
			}

			if (!IFF_Writer_WriteSize(gen->writer, config->sizing, config->typing, body_size))
			{
				goto failure;
			}

			if (body_size > 0)
			{
				struct VPS_Data body_data;
				body_data.bytes = scope->accumulator->bytes;
				body_data.size = body_size;
				body_data.position = 0;
				body_data.limit = body_size;
				body_data.own_bytes = 0;

				if (!IFF_Writer_WriteData(gen->writer, IFF_Header_Encoding_BASE_256, &body_data))
				{
					goto failure;
				}
			}

			if (!IFF_Writer_WritePadding(gen->writer, config, body_size))
			{
				goto failure;
			}
		}
	}

	IFF_WriteScope_Release(scope);
	VPS_List_Node_Release(node);

	return 1;

failure:

	IFF_WriteScope_Release(scope);
	VPS_List_Node_Release(node);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Payload building helpers for directives                            */
/* ------------------------------------------------------------------ */

static char PRIVATE_IFF_Generator_WritePayloadSize
(
	struct VPS_DataWriter *dw
	, const struct IFF_Header_Flags_Fields *config
	, VPS_TYPE_SIZE value
)
{
	return PRIVATE_IFF_Generator_WriteSizeTo(dw, config->sizing, config->typing, value);
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

char IFF_Generator_Allocate
(
	struct IFF_Generator **item
)
{
	struct IFF_Generator *gen;

	if (!item)
	{
		return 0;
	}

	gen = calloc(1, sizeof(struct IFF_Generator));
	if (!gen)
	{
		return 0;
	}

	if (!IFF_Writer_Allocate(&gen->writer))
	{
		goto cleanup;
	}

	if (!VPS_List_Allocate(&gen->scope_stack))
	{
		goto cleanup;
	}

	if (!VPS_List_Allocate(&gen->blobbed_spans))
	{
		goto cleanup;
	}

	*item = gen;

	return 1;

cleanup:

	IFF_Generator_Release(gen);

	return 0;
}

char IFF_Generator_Construct
(
	struct IFF_Generator *item
	, int file_handle
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_Writer_Construct(item->writer, file_handle))
	{
		return 0;
	}

	VPS_List_Construct
	(
		item->scope_stack
		, 0, 0
		, (char(*)(void*))IFF_WriteScope_Release
	);

	VPS_List_Construct
	(
		item->blobbed_spans
		, 0, 0
		, PRIVATE_IFF_Generator_ReleaseBlobbedSpan
	);

	item->file_handle = file_handle;
	item->flags = IFF_HEADER_FLAGS_1985;
	item->form_encoders = 0;
	item->chunk_encoders = 0;

	return 1;
}

char IFF_Generator_ConstructToData
(
	struct IFF_Generator *item
)
{
	if (!item)
	{
		return 0;
	}

	if (!IFF_Writer_ConstructToData(item->writer))
	{
		return 0;
	}

	VPS_List_Construct
	(
		item->scope_stack
		, 0, 0
		, (char(*)(void*))IFF_WriteScope_Release
	);

	VPS_List_Construct
	(
		item->blobbed_spans
		, 0, 0
		, PRIVATE_IFF_Generator_ReleaseBlobbedSpan
	);

	item->file_handle = -1;
	item->flags = IFF_HEADER_FLAGS_1985;
	item->form_encoders = 0;
	item->chunk_encoders = 0;

	return 1;
}

char IFF_Generator_GetOutputData
(
	struct IFF_Generator *gen
	, struct VPS_Data **out_data
)
{
	if (!gen)
	{
		return 0;
	}

	return IFF_Writer_GetOutputData(gen->writer, out_data);
}

char IFF_Generator_Deconstruct
(
	struct IFF_Generator *item
)
{
	if (!item)
	{
		return 0;
	}

	IFF_Writer_Deconstruct(item->writer);
	VPS_List_Deconstruct(item->scope_stack);
	VPS_List_Deconstruct(item->blobbed_spans);

	item->form_encoders = 0;
	item->chunk_encoders = 0;

	return 1;
}

char IFF_Generator_Release
(
	struct IFF_Generator *item
)
{
	if (item)
	{
		IFF_Generator_Deconstruct(item);
		IFF_Writer_Release(item->writer);
		VPS_List_Release(item->scope_stack);
		VPS_List_Release(item->blobbed_spans);
		free(item);
	}

	return 1;
}

/* ------------------------------------------------------------------ */
/*  Segment-level directives                                           */
/* ------------------------------------------------------------------ */

char IFF_Generator_WriteHeader
(
	struct IFF_Generator *gen
	, const struct IFF_Header *header
)
{
	struct VPS_Data *payload = 0;
	struct VPS_DataWriter *dw = 0;
	const struct IFF_Header_Flags_Fields *config;
	char result;

	if (!gen || !header)
	{
		return 0;
	}

	/* IFF header is a segment-level directive; reject if inside a container */
	if (gen->scope_stack->count > 0)
	{
		return 0;
	}

	/* Use IFF-85 config for writing the header directive itself */
	config = &IFF_HEADER_FLAGS_1985.as_fields;

	/* Build payload: version(16BE) + revision(16BE) + flags(64) */
	if (!VPS_Data_Allocate(&payload, 12, 0) || !VPS_Data_Construct(payload))
	{
		VPS_Data_Release(payload);
		return 0;
	}

	if (!VPS_DataWriter_Allocate(&dw) || !VPS_DataWriter_Construct(dw, payload))
	{
		VPS_DataWriter_Release(dw);
		VPS_Data_Release(payload);
		return 0;
	}

	if (!VPS_DataWriter_Write16UBE(dw, header->version))   goto cleanup;
	if (!VPS_DataWriter_Write16UBE(dw, header->revision))  goto cleanup;
	if (!VPS_DataWriter_Write64UBE(dw, header->flags.as_int)) goto cleanup;

	/* Write as directive chunk: tag=' IFF', size, data */
	result = IFF_Writer_WriteChunk(gen->writer, config, &IFF_TAG_SYSTEM_IFF, payload);

	if (result)
	{
		result = IFF_Writer_WritePadding(gen->writer, config, payload->limit);
	}

	if (result)
	{
		gen->flags = header->flags;
	}

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return result;

cleanup:

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return 0;
}

char IFF_Generator_WriteDEF
(
	struct IFF_Generator *gen
	, const struct VPS_Data *identifier
)
{
	struct VPS_Data *payload = 0;
	struct VPS_DataWriter *dw = 0;
	const struct IFF_Header_Flags_Fields *config;
	char result;

	if (!gen || !identifier)
	{
		return 0;
	}

	config = &gen->flags.as_fields;

	/* Payload: num_options(size) + id_size(size) + id_data */
	{
		VPS_TYPE_8U sz_len = IFF_Header_Flags_GetSizeLength(config->sizing);
		VPS_TYPE_SIZE alloc = sz_len * 2 + identifier->limit;

		if (!VPS_Data_Allocate(&payload, alloc, 0) || !VPS_Data_Construct(payload))
		{
			VPS_Data_Release(payload);
			return 0;
		}
	}

	if (!VPS_DataWriter_Allocate(&dw) || !VPS_DataWriter_Construct(dw, payload))
	{
		VPS_DataWriter_Release(dw);
		VPS_Data_Release(payload);
		return 0;
	}

	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, 1))          goto cleanup;
	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, identifier->limit)) goto cleanup;
	if (!VPS_DataWriter_WriteBytes(dw, identifier->bytes, identifier->limit))   goto cleanup;

	result = PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_DEF, payload);

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return result;

cleanup:

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return 0;
}

char IFF_Generator_WriteREF
(
	struct IFF_Generator *gen
	, VPS_TYPE_SIZE num_options
	, const struct VPS_Data **identifiers
)
{
	struct VPS_Data *payload = 0;
	struct VPS_DataWriter *dw = 0;
	const struct IFF_Header_Flags_Fields *config;
	VPS_TYPE_SIZE i;
	char result;

	if (!gen || num_options == 0 || !identifiers)
	{
		return 0;
	}

	config = &gen->flags.as_fields;

	if (!VPS_Data_Allocate(&payload, 128, 0) || !VPS_Data_Construct(payload))
	{
		VPS_Data_Release(payload);
		return 0;
	}

	if (!VPS_DataWriter_Allocate(&dw) || !VPS_DataWriter_Construct(dw, payload))
	{
		VPS_DataWriter_Release(dw);
		VPS_Data_Release(payload);
		return 0;
	}

	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, num_options)) goto cleanup;

	for (i = 0; i < num_options; ++i)
	{
		if (!identifiers[i]) goto cleanup;
		if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, identifiers[i]->limit)) goto cleanup;
		if (!VPS_DataWriter_WriteBytes(dw, identifiers[i]->bytes, identifiers[i]->limit)) goto cleanup;
	}

	result = PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_REF, payload);

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return result;

cleanup:

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Container lifecycle                                                */
/* ------------------------------------------------------------------ */

char IFF_Generator_BeginForm
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
)
{
	return PRIVATE_IFF_Generator_BeginContainer(gen, &IFF_TAG_SYSTEM_FORM, type);
}

char IFF_Generator_EndForm
(
	struct IFF_Generator *gen
)
{
	return PRIVATE_IFF_Generator_EndContainer(gen);
}

char IFF_Generator_BeginList
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
)
{
	return PRIVATE_IFF_Generator_BeginContainer(gen, &IFF_TAG_SYSTEM_LIST, type);
}

char IFF_Generator_EndList
(
	struct IFF_Generator *gen
)
{
	return PRIVATE_IFF_Generator_EndContainer(gen);
}

char IFF_Generator_BeginCat
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
)
{
	return PRIVATE_IFF_Generator_BeginContainer(gen, &IFF_TAG_SYSTEM_CAT, type);
}

char IFF_Generator_EndCat
(
	struct IFF_Generator *gen
)
{
	return PRIVATE_IFF_Generator_EndContainer(gen);
}

char IFF_Generator_BeginProp
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *type
)
{
	return PRIVATE_IFF_Generator_BeginContainer(gen, &IFF_TAG_SYSTEM_PROP, type);
}

char IFF_Generator_EndProp
(
	struct IFF_Generator *gen
)
{
	return PRIVATE_IFF_Generator_EndContainer(gen);
}

/* ------------------------------------------------------------------ */
/*  Chunk data                                                         */
/* ------------------------------------------------------------------ */

char IFF_Generator_WriteChunk
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
)
{
	if (!gen || !tag)
	{
		return 0;
	}

	/* Validate: chunks only allowed in FORM and PROP */
	if (!PRIVATE_IFF_Generator_ValidateChunkAllowed(gen))
	{
		return 0;
	}

	return PRIVATE_IFF_Generator_EmitTrackedChunk(gen, tag, data);
}

/* ------------------------------------------------------------------ */
/*  Checksum spans                                                     */
/* ------------------------------------------------------------------ */

char IFF_Generator_BeginChecksumSpan
(
	struct IFF_Generator *gen
	, const struct VPS_Set *algorithm_ids
)
{
	struct VPS_Data *payload = 0;
	struct VPS_DataWriter *dw = 0;
	const struct IFF_Header_Flags_Fields *config;
	VPS_TYPE_SIZE num_ids = 0;
	VPS_TYPE_SIZE i;
	char result;

	if (!gen || !algorithm_ids)
	{
		return 0;
	}

	config = &gen->flags.as_fields;

	/* Count entries in the set */
	for (i = 0; i < algorithm_ids->buckets; ++i)
	{
		num_ids += algorithm_ids->bucket_vector[i]->count;
	}

	/* Build CHK payload: version(size) + num_ids(size) + {id_size, id_data}... */
	if (!VPS_Data_Allocate(&payload, 128, 0) || !VPS_Data_Construct(payload))
	{
		VPS_Data_Release(payload);
		return 0;
	}

	if (!VPS_DataWriter_Allocate(&dw) || !VPS_DataWriter_Construct(dw, payload))
	{
		VPS_DataWriter_Release(dw);
		VPS_Data_Release(payload);
		return 0;
	}

	/* Version = 1 */
	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, 1)) goto cleanup;
	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, num_ids)) goto cleanup;

	for (i = 0; i < algorithm_ids->buckets; ++i)
	{
		struct VPS_List *bucket = algorithm_ids->bucket_vector[i];
		struct VPS_List_Node *entry_node = bucket->head;

		while (entry_node)
		{
			struct VPS_Set_Entry *set_entry = entry_node->data;
			struct VPS_Data *id_data = set_entry->item;
			VPS_TYPE_SIZE id_len = strlen((const char *)id_data->bytes);

			if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, id_len)) goto cleanup;
			if (!VPS_DataWriter_WriteBytes(dw, id_data->bytes, id_len))      goto cleanup;

			entry_node = entry_node->next;
		}
	}

	/* Write the CHK directive chunk (tracked) */
	result = PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_CHK, payload);

	/* Start the span: blobbed mode tracks on accumulator, progressive on tap */
	if (result)
	{
		if (PRIVATE_IFF_Generator_IsBlobbed(gen))
		{
			result = PRIVATE_IFF_Generator_BeginBlobbedSpan(gen, algorithm_ids);
		}
		else
		{
			result = IFF_WriteTap_StartSpan(gen->writer->tap, algorithm_ids);
		}
	}

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return result;

cleanup:

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);

	return 0;
}

char IFF_Generator_EndChecksumSpan
(
	struct IFF_Generator *gen
)
{
	struct VPS_Dictionary *computed_checksums = 0;
	struct VPS_Data *payload = 0;
	struct VPS_DataWriter *dw = 0;
	const struct IFF_Header_Flags_Fields *config;
	VPS_TYPE_SIZE num_entries = 0;
	VPS_TYPE_SIZE b;
	char result;

	if (!gen)
	{
		return 0;
	}

	config = &gen->flags.as_fields;

	/* End the span: blobbed mode computes from accumulator, progressive from tap */
	if (PRIVATE_IFF_Generator_IsBlobbed(gen))
	{
		if (!PRIVATE_IFF_Generator_EndBlobbedSpan(gen, &computed_checksums))
		{
			return 0;
		}
	}
	else
	{
		/*
		 * Feed SUM tag bytes to active spans before ending. The parser's
		 * content loop reads the SUM tag through the DataTap before
		 * Parse_Directive pauses the span, so those tag bytes are included
		 * in the parser's checksum. We include them here too so both sides
		 * agree on which bytes are checksummed. (Mirrors the blobbed path
		 * at PRIVATE_IFF_Generator_EndBlobbedSpan lines 195-228.)
		 */
		{
			VPS_TYPE_8U tag_length = IFF_Header_Flags_GetTagLength(config->tag_sizing);

			if (tag_length > 0)
			{
				unsigned char sum_tag_buf[IFF_TAG_CANONICAL_SIZE];
				struct VPS_Data sum_tag_wrapper;
				struct VPS_List_Node *span_node;

				memcpy(sum_tag_buf, IFF_TAG_SYSTEM_SUM.data + (IFF_TAG_CANONICAL_SIZE - tag_length), tag_length);
				memset(&sum_tag_wrapper, 0, sizeof(sum_tag_wrapper));
				sum_tag_wrapper.bytes = sum_tag_buf;
				sum_tag_wrapper.size = tag_length;
				sum_tag_wrapper.limit = tag_length;

				span_node = gen->writer->tap->active_spans->head;
				while (span_node)
				{
					struct IFF_ChecksumSpan *span = span_node->data;
					struct VPS_List_Node *calc_node = span->calculators->head;
					while (calc_node)
					{
						struct IFF_ChecksumCalculator *calc = calc_node->data;
						if (calc->algorithm && calc->algorithm->update)
						{
							calc->algorithm->update(calc->context, &sum_tag_wrapper);
						}
						calc_node = calc_node->next;
					}
					span_node = span_node->next;
				}
			}
		}

		if (!IFF_WriteTap_EndSpan(gen->writer->tap, &computed_checksums))
		{
			return 0;
		}
	}

	/* Build SUM payload: version(size) + num_entries(size) + {id_size, id, sum_size, sum}... */
	if (!VPS_Data_Allocate(&payload, 128, 0) || !VPS_Data_Construct(payload))
	{
		VPS_Data_Release(payload);
		VPS_Dictionary_Release(computed_checksums);
		return 0;
	}

	if (!VPS_DataWriter_Allocate(&dw) || !VPS_DataWriter_Construct(dw, payload))
	{
		VPS_DataWriter_Release(dw);
		VPS_Data_Release(payload);
		VPS_Dictionary_Release(computed_checksums);
		return 0;
	}

	/* Count entries */
	num_entries = computed_checksums->total_entries;

	/* Version = 1 */
	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, 1))           goto cleanup;
	if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, num_entries)) goto cleanup;

	for (b = 0; b < computed_checksums->buckets; ++b)
	{
		struct VPS_List *bucket = computed_checksums->bucket_vector[b];
		if (!bucket) continue;
		struct VPS_List_Node *node = bucket->head;

		while (node)
		{
			struct VPS_Dictionary_Entry *entry = node->data;
			const char *id = (const char *)entry->key;
			struct VPS_Data *checksum = (struct VPS_Data *)entry->data;
			VPS_TYPE_SIZE id_len = strlen(id);

			if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, id_len))               goto cleanup;
			if (!VPS_DataWriter_WriteBytes(dw, (const unsigned char *)id, id_len))          goto cleanup;
			if (!PRIVATE_IFF_Generator_WritePayloadSize(dw, config, checksum->limit))      goto cleanup;
			if (!VPS_DataWriter_WriteBytes(dw, checksum->bytes, checksum->limit))           goto cleanup;

			node = node->next;
		}
	}

	/* Write the SUM directive chunk (AFTER ending the span, so SUM bytes aren't checksummed) */
	result = PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_SUM, payload);

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);
	VPS_Dictionary_Release(computed_checksums);

	return result;

cleanup:

	VPS_DataWriter_Release(dw);
	VPS_Data_Release(payload);
	VPS_Dictionary_Release(computed_checksums);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Filler and shard directives                                        */
/* ------------------------------------------------------------------ */

char IFF_Generator_WriteFiller
(
	struct IFF_Generator *gen
	, VPS_TYPE_SIZE size
)
{
	struct VPS_Data *filler = 0;
	char result;

	if (!gen)
	{
		return 0;
	}

	if (size > 0)
	{
		if (!VPS_Data_Allocate(&filler, size, size))
		{
			return 0;
		}

		memset(filler->bytes, 0, size);
	}

	result = PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_SHARD, filler);

	VPS_Data_Release(filler);

	return result;
}

char IFF_Generator_WriteShard
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
)
{
	if (!gen)
	{
		return 0;
	}

	/* Sharding must be enabled */
	if (!(gen->flags.as_fields.structuring & IFF_Header_Flag_Structuring_SHARDING))
	{
		return 0;
	}

	return PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_SHARD, data);
}

/* ------------------------------------------------------------------ */
/*  Version and revision directives                                    */
/* ------------------------------------------------------------------ */

char IFF_Generator_WriteVER
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
)
{
	if (!gen)
	{
		return 0;
	}

	return PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_VER, data);
}

char IFF_Generator_WriteREV
(
	struct IFF_Generator *gen
	, const struct VPS_Data *data
)
{
	if (!gen)
	{
		return 0;
	}

	return PRIVATE_IFF_Generator_EmitTrackedChunk(gen, &IFF_TAG_SYSTEM_REV, data);
}

/* ------------------------------------------------------------------ */
/*  Factory-driven encoding                                            */
/* ------------------------------------------------------------------ */

char IFF_Generator_EncodeForm
(
	struct IFF_Generator *gen
	, const struct IFF_Tag *form_type
	, void *source_entity
)
{
	struct IFF_FormEncoder *encoder = 0;
	struct IFF_Generator_State state;
	void *custom_state = 0;
	struct IFF_Tag chunk_tag;
	struct VPS_Data *chunk_data = 0;
	char done = 0;

	if (!gen || !form_type || !gen->form_encoders)
	{
		return 0;
	}

	/* Look up FormEncoder by form_type */
	if (!VPS_Dictionary_Find(gen->form_encoders, (void *)form_type, (void **)&encoder))
	{
		return 0;
	}

	state.generator = gen;
	state.flags = gen->flags;

	/* Begin the FORM */
	if (!IFF_Generator_BeginForm(gen, form_type))
	{
		return 0;
	}

	/* Call begin_encode */
	if (encoder->begin_encode)
	{
		if (!encoder->begin_encode(&state, source_entity, &custom_state))
		{
			IFF_Generator_EndForm(gen);
			return 0;
		}
	}

	/* Produce chunks */
	if (encoder->produce_chunk)
	{
		done = 0;
		while (!done)
		{
			chunk_data = 0;
			memset(&chunk_tag, 0, sizeof(chunk_tag));

			if (!encoder->produce_chunk(&state, custom_state, &chunk_tag, &chunk_data, &done))
			{
				goto encode_failure;
			}

			if (!done && chunk_data)
			{
				struct IFF_ChunkEncoder *chunk_encoder = 0;
				struct VPS_Data *write_data = chunk_data;

				/* If a ChunkEncoder is registered for this tag, use it */
				if (gen->chunk_encoders
					&& VPS_Dictionary_Find(gen->chunk_encoders, (void *)&chunk_tag, (void **)&chunk_encoder)
					&& chunk_encoder && chunk_encoder->encode)
				{
					struct VPS_Data *encoded_data = 0;

					if (!chunk_encoder->encode(&state, chunk_data, &encoded_data))
					{
						VPS_Data_Release(chunk_data);
						goto encode_failure;
					}

					VPS_Data_Release(chunk_data);
					write_data = encoded_data;
				}

				if (!IFF_Generator_WriteChunk(gen, &chunk_tag, write_data))
				{
					VPS_Data_Release(write_data);
					goto encode_failure;
				}

				VPS_Data_Release(write_data);
			}
		}
	}

	/* Produce nested forms */
	if (encoder->produce_nested_form)
	{
		done = 0;
		while (!done)
		{
			struct IFF_Tag nested_type;
			void *nested_entity = 0;

			memset(&nested_type, 0, sizeof(nested_type));

			if (!encoder->produce_nested_form(&state, custom_state, &nested_type, &nested_entity, &done))
			{
				goto encode_failure;
			}

			if (!done)
			{
				if (!IFF_Generator_EncodeForm(gen, &nested_type, nested_entity))
				{
					goto encode_failure;
				}
			}
		}
	}

	/* End encode */
	if (encoder->end_encode)
	{
		encoder->end_encode(&state, custom_state);
	}

	return IFF_Generator_EndForm(gen);

encode_failure:

	if (encoder->end_encode)
	{
		encoder->end_encode(&state, custom_state);
	}

	IFF_Generator_EndForm(gen);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Finalize                                                           */
/* ------------------------------------------------------------------ */

char IFF_Generator_Flush
(
	struct IFF_Generator *gen
)
{
	if (!gen)
	{
		return 0;
	}

	/* Fail if containers are still open */
	if (gen->scope_stack->count > 0)
	{
		return 0;
	}

	/* Fail if checksum spans are still open */
	if (gen->blobbed_spans->count > 0)
	{
		return 0;
	}

	return IFF_Writer_Flush(gen->writer);
}
