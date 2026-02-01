Implementation Plan: ' CHK' / ' SUM' Integrity Spans
=====================================================

Last updated: 2026-02-22


Design Decision
---------------

CHK/SUM handling lives in the **Reader layer**, not the Parser.

Rationale:
- The Reader owns the DataTap (the checksum state machine).
- Checksum spans are a stream-level concern, not a semantic concern.
- The Parser should not reach through `parser->reader->tap` to manipulate
  low-level I/O state.
- Consistent with `notes.txt` architecture diagram where the Parser calls
  into the checked_reader (now DataTap, owned by Reader).

The Parser remains responsible for:
1. Detecting ' CHK' and ' SUM' directive tags.
2. Reading the directive chunk (size + payload).
3. Calling Reader-level span methods with the raw payload.

The Reader is responsible for:
1. Parsing the binary payload format.
2. Translating identifiers into registered algorithms.
3. Delegating to DataTap's StartSpan / EndSpan.


Step 1: Add Reader API
-----------------------

**File**: `include/IFF/IFF_Reader.h`

Add two new public functions:

```c
char IFF_Reader_StartChecksumSpan
(
    struct IFF_Reader* reader
    , const struct IFF_Header_Flags_Fields* config
    , const struct VPS_Data* chk_payload
);

char IFF_Reader_EndChecksumSpan
(
    struct IFF_Reader* reader
    , const struct IFF_Header_Flags_Fields* config
    , const struct VPS_Data* sum_payload
);
```

Parameters:
- `config`: current scope flags (needed to interpret size fields within the
  payload, per spec: "sizes are subject to size length rules").
- `chk_payload` / `sum_payload`: the raw data from the directive chunk.


Step 2: Implement Payload Parsing
----------------------------------

**File**: `src/IFF_Reader.c`

### StartChecksumSpan (CHK payload format)

```
[version: size_len bytes]
[num_ids: size_len bytes]
for each id:
    [id_len: size_len bytes]
    [id_data: id_len bytes]
```

Implementation:
1. Wrap `chk_payload` in a `VPS_DataReader`.
2. Read `version` (currently expect 1).
3. Read `num_ids`.
4. For each id: read `id_len`, read `id_data`, add to a `VPS_Set`.
5. Call `IFF_DataTap_StartSpan(reader->tap, &algorithm_set)`.
6. Release the set.

### EndChecksumSpan (SUM payload format)

```
[version: size_len bytes]
[num_ids: size_len bytes]
for each id:
    [id_len: size_len bytes]
    [id_data: id_len bytes]
    [sum_len: size_len bytes]
    [sum_data: sum_len bytes]
```

Implementation:
1. Wrap `sum_payload` in a `VPS_DataReader`.
2. Read `version` (currently expect 1).
3. Read `num_ids`.
4. For each id: read `id_len` + `id_data` + `sum_len` + `sum_data`.
   Build a `VPS_Dictionary` mapping identifier strings to expected
   checksum `VPS_Data` blobs.
5. Call `IFF_DataTap_EndSpan(reader->tap, expected_checksums)`.
6. Release the dictionary.
7. Return the match result from EndSpan.

**Size field interpretation**: The `id_len` and `sum_len` fields inside
the payload follow the current scope's sizing rules. Use
`IFF_Reader_PRIVATE_InterpretSize()` (already implemented as a static
helper in IFF_Reader.c) to decode them. Note: the static helper needs
to be made accessible within the file, or the parsing can use
VPS_DataReader read methods directly since the payload is already in
a VPS_Data buffer.


Step 3: Wire into Parse_Directive
----------------------------------

**File**: `src/IFF_Parser.c`

In `PRIVATE_IFF_Parser_Parse_Directive`, add explicit handling between
' END' and ' IFF':

```c
// --- ' CHK' ---
IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_CHK, &ordering);
if (ordering == 0)
{
    // Read the directive chunk.
    result = IFF_Reader_ReadChunk(parser->reader, &flags.as_fields, &tag, &chunk);
    if (!result) return 0;

    // Track boundary.
    scope->boundary.level += IFF_Header_Flags_GetSizeLength(flags.as_fields.sizing)
        + chunk->size;

    // Handle padding.
    if (!(flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING)
        && (chunk->size & 1))
    {
        IFF_Reader_Skip(parser->reader, 1);
        scope->boundary.level += 1;
    }

    // Delegate payload parsing to the Reader.
    result = IFF_Reader_StartChecksumSpan(
        parser->reader, &flags.as_fields, chunk->data);

    IFF_Chunk_Release(chunk);
    return result;
}

// --- ' SUM' ---
IFF_Tag_Compare(&tag, &IFF_TAG_SYSTEM_SUM, &ordering);
if (ordering == 0)
{
    // Same read + boundary + padding pattern as CHK.
    ...

    result = IFF_Reader_EndChecksumSpan(
        parser->reader, &flags.as_fields, chunk->data);

    IFF_Chunk_Release(chunk);
    return result;
}
```

Alternatively, both CHK and SUM could still go through
`ReadAndExecuteDirective` (which handles the read + boundary + padding),
with ExecuteDirective producing `IFF_ACTION_START_CHECKSUM` or
`IFF_ACTION_END_CHECKSUM`, and the action handler calling the Reader
methods. This keeps Parse_Directive smaller but adds indirection.

**Recommended**: Direct handling (like ' END'), since these interact with
Reader internals that the generic processor interface cannot reach.


Step 4: VPS_Set Dependency
---------------------------

`IFF_DataTap_StartSpan` expects a `VPS_Set`. The Reader will need to:
1. Include `<vulpes/VPS_Set.h>`.
2. Allocate/construct a temporary VPS_Set.
3. Add each algorithm identifier string.
4. Pass to StartSpan.
5. Release the set.

Verify that VPS_Set supports string items and that the set's hash/compare
callbacks match what StartSpan iterates over (it accesses
`set_entry->item` as a `VPS_Data*` whose `bytes` are the identifier string).


Step 5: Testing
----------------

Create a test that:
1. Registers a checksum algorithm (e.g., a trivial XOR-based one).
2. Constructs a binary IFF-2025 stream in memory with:
   - ' IFF' directive (version 40)
   - FORM ILBM
   - ' CHK' directive (1 algorithm: "TEST-XOR")
   - BMHD chunk (known data)
   - ' SUM' directive (expected XOR checksum)
3. Parses the stream and verifies EndSpan returns 1 (match).
4. Repeats with a wrong expected checksum to verify failure.


Open Questions
--------------

1. **Size fields within CHK/SUM payload**: The spec says "sizes are subject
   to size length rules". Does this mean `id_len` and `sum_len` are encoded
   using the current scope's sizing (2/4/8 bytes, LE/BE, signed/unsigned)?
   Or are they always a fixed small integer? The spec example uses simple
   integers (e.g., `7` for "CRC-32C" length), suggesting they follow the
   current scope's size encoding.

2. **Version field**: The spec shows `version` in the payload. What values
   are defined? The example uses `1`. Should the parser reject unknown
   versions or skip them?

3. **Partial algorithm support**: If a ' CHK' lists multiple algorithms and
   the host only has some registered, should it activate the subset it knows
   (lenient) or fail (strict)? The DataTap's current StartSpan silently
   skips unregistered algorithms.
