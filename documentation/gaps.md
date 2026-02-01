IFF-2025 Spec Compliance Gaps
=============================

Last updated: 2026-02-23 (all read-side and write-side gaps resolved)

This document lists features required by the IFF-2025 specification that are
not yet implemented. All read-side gaps are resolved. The write path
(IFF_Generator + IFF_Writer stack) is now complete, providing both
progressive and blobbed mode output, directive writing, checksum generation
(both progressive and blobbed modes), content-type validation, bytes_written
tracking, flush validation, and encoder vtable dispatch. See
`documentation/architecture-writer.md` for details.


Gap 1: ' CHK' / ' SUM' Not Wired (Integrity Spans) -- RESOLVED
-----------------------------------------------------------------

**Spec reference**: Section 5.2

**Resolution**: Implemented across two layers:

- `include/IFF/IFF_Reader.h` + `src/IFF_Reader.c`: Added
  `IFF_Reader_StartChecksumSpan` and `IFF_Reader_EndChecksumSpan`. These
  parse the binary CHK/SUM payload format (version, num_ids, identifier
  strings, expected checksums) using `VPS_DataReader`, build `VPS_Set` /
  `VPS_Dictionary` structures, and delegate to `IFF_DataTap_StartSpan` /
  `IFF_DataTap_EndSpan`.
- `src/IFF_Parser.c`, `Parse_Directive`: Added direct handling for `' CHK'`
  and `' SUM'` tags before the `' IFF'` handler. Each reads the directive
  chunk, tracks boundary + padding, and calls the corresponding Reader-level
  span method.


Gap 2: No Checksum Algorithm Implementations -- RESOLVED
----------------------------------------------------------

**Spec reference**: Section 5.2 (algorithm table)

**Resolution**: All four spec-defined algorithms are now implemented:

| Algorithm    | Identifier     | Output | File                       |
|--------------|----------------|--------|----------------------------|
| LRC-ISO-1155 | "LRC-ISO-1155" | 8-bit  | `src/IFF_Checksum_LRC.c`   |
| RFC-1071     | "RFC-1071"     | 16-bit | `src/IFF_Checksum_RFC1071.c` |
| CRC-32C      | "CRC-32C"      | 32-bit | `src/IFF_Checksum_CRC32C.c`  |
| CRC64-ECMA   | "CRC64-ECMA"   | 64-bit | `src/IFF_Checksum_CRC64ECMA.c` |

Each module implements the `IFF_ChecksumAlgorithm` vtable (`create_context`,
`update`, `finalize`, `release_context`) and exposes a `Get()` function
returning a pointer to a static const algorithm instance. CRC-32C uses
reflected polynomial 0x82F63B78; CRC-64/ECMA uses MSB-first polynomial
0x42F0E1EBA9EA3693. Both use lazily-initialized 256-entry lookup tables.
All checksum outputs are stored big-endian.

To register: `IFF_DataTap_RegisterAlgorithm(tap, IFF_Checksum_CRC32C_Get())`.


Gap 3: Sharding ('    ' Directive) -- RESOLVED
-------------------------------------------------

**Spec reference**: Section 6.1

**Resolution**: Implemented across `IFF_Scope` and `IFF_Parser`:

- `include/IFF/IFF_Scope.h`: Added three shard-tracking fields to
  `IFF_Scope`: `last_chunk_decoder`, `last_chunk_state`, `last_chunk_tag`.
  These store the pending chunk decoder between shard continuations.
- `src/IFF_Parser.c`, `FlushLastDecoder`: New private helper that finalizes
  the pending chunk decoder (calls `end_decode`), routes the result through
  the PROP-vs-FORM logic, and clears the shard-tracking fields.
- `src/IFF_Parser.c`, `Parse_Chunk`: When `SHARDING` is enabled and a chunk
  decoder is found, flushes any previous pending decoder, then begins the new
  decoder and stores it in scope fields (deferring `end_decode`). When
  `SHARDING` is off, the immediate lifecycle is unchanged.
- `src/IFF_Parser.c`, `Parse_Directive`: Added explicit handling for
  `IFF_TAG_SYSTEM_SHARD` (`'    '`). When `SHARDING` is set, reads the chunk
  and dispatches its data to the pending decoder's `process_shard()`. When
  not set, falls through to existing filler behavior.
- Flush calls inserted at all scope exit points: before nested container
  dispatch in FORM, at `form_done`, `form_cleanup`, `prop_done`, and PROP
  error exits.


Gap 4: Strict Container Validation -- RESOLVED
------------------------------------------------

**Spec reference**: Section 4.2 (CAT/LIST type enforcement), Section 8.3
(Structuring Bit 2)

**Resolution**: Implemented in `Parse_Container_FORM` (`src/IFF_Parser.c`).
After reading the FORM type tag, the parser checks whether the parent scope
is a CAT or LIST with `STRICT_CONTAINERS` enabled and a non-wildcard type.
If so, the FORM type must match the parent's declared type or parsing fails.
Validation is done inside FORM (option B from `plan-remaining.md`) since the
parent scope is still accessible at that point.


Gap 5: Scope Guards (Child vs. Parent Flags) -- RESOLVED
-----------------------------------------------------------

**Spec reference**: Section 5 (guard rules)

**Resolution**: Implemented in `IFF_Parser_ExecuteDirective`
(`src/IFF_Parser.c`), `IFF_ACTION_UPDATE_FLAGS` case. Three validation
checks run before applying new flags:

1. **Size widening guard**: Rejects if the new size field width exceeds the
   parent's. A 64-bit child inside a 32-bit parent would produce sizes the
   parent can't represent.
2. **Blobbed-to-progressive guard**: Rejects if the parent is BLOBBED and the
   child wants PROGRESSIVE. Progressive mode requires `' END'` which falls
   outside the parent's declared boundary.
3. **Tag widening guard**: Rejects if the new tag width exceeds the parent's.
   Wider tags would misalign the parent's boundary tracking.

The parent scope is accessed via `scope_stack->head->next->data`. If there is
no parent (top-level scope), the guards are skipped — there is no constraint
to violate.


Gap 6: IFF-85 Mode Locking -- RESOLVED
----------------------------------------

**Spec reference**: Section 9 (bootstrapping), Section 9.1.3

**Resolution**: Implemented across two files:
- `include/IFF/IFF_Parser_Session.h`: Added `char iff85_locked` field to
  `IFF_Parser_Session`. When set to 1, the stream was identified as IFF-85
  during bootstrap (first tag was a container, not `' IFF'`).
- `src/IFF_Parser.c`, `Parse_Segment`: Sets `session->iff85_locked = 1`
  when the first tag is a container (FORM/LIST/CAT).
- `src/IFF_Parser.c`, `Parse_Directive`: Guard at the top rejects all
  directives when `iff85_locked` is set, except `'    '` which acts as
  filler (read and skip via the generic handler).


Gap 7: ' DEF' / ' REF' (Segmentation & Inclusion) -- RESOLVED
----------------------------------------------------------------

**Spec reference**: Sections 6.2--6.5

**Resolution**: Implemented using a reader-swap model (no recursive
`Parse_Segment`):

- `include/IFF/IFF_ReaderFrame.h` + `src/IFF_ReaderFrame.c`: New struct
  that saves reader state (reader pointer, file handle, iff85_locked) when
  pushing onto the reader stack. Lifecycle: Allocate, Construct, Deconstruct
  (no-op), Release.
- `include/IFF/IFF_Parser.h`: Added `IFF_SegmentResolverFn` callback typedef,
  `segment_resolver`, `resolver_context`, and `reader_stack` (VPS_List) fields
  to `IFF_Parser`. Added `IFF_Parser_SetSegmentResolver`.
- `include/IFF/IFF_Parser_Session.h`: Added `SegmentSwitch` state to the
  session state enum and `parsing_resumed` field to the session struct.
- `include/IFF/IFF_Reader.h` + `src/IFF_Reader.c`: Exposed
  `IFF_Reader_ReadPayloadSize` (formerly private) for payload parsing.
- `src/IFF_Parser.c`:
  - `PushReaderAndSwitch`: Saves current reader into a frame, pushes onto
    reader_stack (max depth 16), creates new reader for the included file,
    sets `SegmentSwitch` state.
  - `PopReaderAndRestore`: Pops frame, releases included reader, closes
    included file handle, restores parent reader, sets `parsing_resumed`.
  - `HandleSegmentRef`: Reads REF payload (num_options, id_size/id_data
    pairs), tries each option with the segment resolver callback, calls
    `PushReaderAndSwitch` on success. Supports optional (id_size=0) entries.
  - `Parse_Segment`: Intercepts `' REF'` in the directive case, handles EOF
    during inclusion (pops reader stack), handles `' END'` at global scope
    during inclusion, uses `parsing_resumed` to prevent false IFF-85 bootstrap.
  - `Parse_Directive`: Added explicit `' DEF'` case (consumed via
    `ReadAndExecuteDirective`).
  - `Scan`: Replaced `IsActive` loop with explicit state check so
    `SegmentSwitch` re-enters `Parse_Segment` for the new/restored segment.
  - `Deconstruct`: Unwinds reader_stack before releasing the root reader.
