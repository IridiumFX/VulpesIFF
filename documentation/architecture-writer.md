# IFF-2025 Write-Side Architecture

## Decorator Stack

The write-side mirrors the read-side decorator pattern:

```
IFF_Generator       High-level: scope management, encoder dispatch
    |
IFF_Writer          Interpretation: write tags, sizes, chunks
    |
IFF_WriteTap        Transparent checksum accumulation on every byte written
    |
IFF_WritePump       Raw I/O: VPS_StreamWriter buffering
    |
File / Socket
```

Each layer adds a specific concern without the layers above or below
needing to know about it.

## Progressive vs Blobbed Mode

### Progressive Mode (`IFF_Header_Operating_PROGRESSIVE`)

Streaming-friendly. Containers have no declared size and are terminated
by `' END'` directives.

```
BeginForm:   writes FORM tag, type tag (no size)
WriteChunk:  writes tag + size + data + padding
EndForm:     writes ' END' tag + size=0
```

All writes go directly through the IFF_Writer to the file.

### Blobbed Mode (`IFF_Header_Operating_BLOBBED`)

Standard IFF-85 mode. Containers declare their size upfront. Since the
file descriptor may be non-seekable (pipe, socket), sizes cannot be
backpatched. Instead, container contents accumulate in memory.

```
BeginForm:   pushes scope with VPS_Data accumulator, writes type tag into accumulator
WriteChunk:  writes tag + size + data + padding into accumulator
EndForm:     writes FORM tag + size(accumulator.limit) + accumulator contents to parent
```

### Output Target Abstraction

The Generator's internal `Emit*` helpers check the current scope:

- If the scope has an `accumulator_writer` (blobbed) -> write to buffer
- If no accumulator (progressive or root level) -> write to IFF_Writer

This keeps the container lifecycle code (`BeginForm`, `WriteChunk`,
`EndForm`) largely mode-agnostic.

### Nested Blobbed Containers

When a blobbed FORM is nested inside a blobbed LIST:

1. Inner FORM accumulates into its own `accumulator`
2. On `EndForm`, inner FORM's serialized bytes (tag + size + body) append
   to the outer LIST's `accumulator`
3. On `EndList`, outer LIST writes to the file (or its parent's accumulator)

This handles arbitrary nesting depth naturally.

## Checksum Generation Lifecycle

### Progressive Mode

1. `BeginChecksumSpan`: builds and writes `' CHK'` directive, then calls
   `IFF_WriteTap_StartSpan` -- all subsequent bytes flow through the tap's
   checksum calculators
2. (write chunks, containers, etc.)
3. `EndChecksumSpan`: calls `IFF_WriteTap_EndSpan` which finalizes
   calculators and returns computed checksums. Then builds and writes
   `' SUM'` directive with the computed values.

The `' SUM'` bytes are written _after_ the span ends, so they are not
included in the checksum calculation (matching spec semantics).

### Blobbed Mode

In blobbed mode, writes go to in-memory accumulators rather than through
the WriteTap, so the tap's checksum calculators do not see the data.
Checksum generation in blobbed mode is not currently supported.

## Encoder Vtable Contracts

### IFF_ChunkEncoder

Single function: `encode(state, source_object, out_data)` -- produces
raw bytes from a structured object. Simpler than the decoder side
(no sharding on encode).

### IFF_FormEncoder

Four-function lifecycle mirroring IFF_FormDecoder:

1. `begin_encode(state, source_entity, custom_state)` -- set up state
2. `produce_chunk(state, custom_state, out_tag, out_data, out_done)` --
   produce chunks one at a time, set done=1 when finished
3. `produce_nested_form(state, custom_state, out_type, out_entity, out_done)` --
   produce nested FORMs, set done=1 when finished
4. `end_encode(state, custom_state)` -- cleanup

### Factory-Driven Generation

`IFF_Generator_EncodeForm(gen, form_type, source_entity)`:

1. Look up FormEncoder by form_type
2. Call begin_encode
3. Loop produce_chunk -> WriteChunk for each
4. Loop produce_nested_form -> recurse EncodeForm for each
5. Call end_encode

## Segment Writing

### DEF (`' DEF'`)

`WriteDEF(gen, identifier)` -- declares this segment's identity.
Payload: `[num_options=1, id_size, id_data]`.

### REF (`' REF'`)

`WriteREF(gen, num_options, identifiers[])` -- references external segments.
Payload: `[num_options, {id_size, id_data}...]`.

## Relationship to Read-Side

| Write-Side | Read-Side | Role |
|------------|-----------|------|
| IFF_WritePump | IFF_DataPump | Raw I/O |
| IFF_WriteTap | IFF_DataTap | Checksum accumulation |
| IFF_Writer | IFF_Reader | Tag/size/data interpretation |
| IFF_WriteScope | IFF_Scope | Per-container state |
| IFF_Generator | IFF_Parser | High-level orchestration |
| IFF_FormEncoder | IFF_FormDecoder | FORM vtable |
| IFF_ChunkEncoder | IFF_ChunkDecoder | Chunk vtable |
| IFF_Generator_Factory | IFF_Parser_Factory | Builder pattern |
| IFF_Generator_State | IFF_Parser_State | Encoder-facing view |
| VPS_DataWriter | VPS_DataReader | Sequential buffer access |
| VPS_StreamWriter | VPS_StreamReader | Buffered file I/O |

The write-side types share checksum infrastructure with the read-side:
`IFF_ChecksumAlgorithm`, `IFF_ChecksumCalculator`, and `IFF_ChecksumSpan`
are direction-agnostic and used by both IFF_DataTap and IFF_WriteTap.
