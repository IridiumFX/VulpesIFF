IFF Parser Implementation Status
================================

Last updated: 2026-02-23 (write path complete: blobbed checksums, validation, tracking)


1. Architecture Overview
------------------------

The implementation follows the layered decorator pattern described in
`notes.txt`:

```
IFF_Parser         High-level logic: scope management, decoder dispatch
    |
IFF_Reader         Interpretation: tags, sizes, chunks, checksum spans
    |
IFF_DataTap        Transparent checksum accumulation on every byte read
    |
IFF_DataPump       Raw I/O: VPS_StreamReader + VPS_DataReader buffering
    |
File / Socket
```

Supporting infrastructure:

- **IFF_Parser_Session** -- Scope stack (VPS_List), active scope pointer,
  session state machine, PROP storage (VPS_ScopedDictionary).
- **IFF_Parser_State** -- Decoder-facing view into the session; exposes
  `FindProp` without coupling decoders to session internals.
- **IFF_Parser_Factory** -- Builder that owns decoder/processor registries
  (VPS_Dictionary) and constructs configured Parser instances.
- **IFF_Scope** -- Per-container state: flags, boundary, variant/type tags,
  active FormDecoder + its custom state.
- **IFF_Boundary** -- Tracks `level` (bytes consumed) against `limit`
  (declared container size, or 0 for unbounded/progressive).


2. What Works Today
-------------------

### Core Parser Loop

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| Parse_Segment (top-level loop)   | Done     | Handles IFF/container dispatch     |
| Parse_Container_FORM             | Done     | Size, type validation, scope, decoder lifecycle |
| Parse_Container_LIST             | Done     | PROP + container nesting           |
| Parse_Container_CAT              | Done     | Container-only nesting             |
| Parse_PROP                       | Done     | Flat chunks, PROP storage via ScopedDictionary |
| Parse_Chunk                      | Done     | Decoder lookup, raw fallback, PROP/FORM routing |
| Parse_Directive                  | Done     | ' END', ' IFF', ' DEF', IFF-85 guard, generic fallthrough |
| HandleSegmentRef (' REF')        | Done     | Multi-option resolver, reader swap |
| IFF_Parser_Scan (entry point)    | Done     | Loops segments until Complete/Failed/SegmentSwitch |

### Tag System

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| 4/8/16-byte tag reading          | Done     | Via IFF_Header_Flags_GetTagLength  |
| Canonical normalization          | Done     | Right-pad data, left-pad directive |
| Type classification              | Done     | TAG, CONTAINER, SUBCONTAINER, DIRECTIVE |
| Container reclassification       | Done     | Post-construct memcmp against FORM/LIST/CAT/PROP |
| Tag comparison + hashing         | Done     | FNV-1a on type + canonical data    |

### Session & Scope

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| Scope stack (push/pop)           | Done     | VPS_List as LIFO                   |
| EnterScope / LeaveScope          | Done     | Mirrors ScopedDictionary           |
| IsActive                         | Done     | Not Failed/Complete                |
| IsBoundaryOpen                   | Done     | limit==0 (unbounded) or level<limit |
| SetState                         | Done     | Simple setter                      |
| PROP storage (AddProp)           | Done     | Composite IFF_Chunk_Key            |
| PROP resolution (FindProp)       | Done     | Type-specific then wildcard fallback |

### Sizing & Typing

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| 16/32/64-bit size fields         | Done     | IFF_Reader_ReadSize                |
| Signed / unsigned                | Done     | Sign-extension handled             |
| Big-endian / little-endian       | Done     | VPS_Endian helpers                 |

### Operating Modes

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| Blobbed mode (sized containers)  | Done     | Boundary tracking per scope        |
| Progressive mode (' END')        | Done     | scope_ended flag breaks loop       |

### Padding

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| Default even-byte padding        | Done     | Skip 1 byte for odd-size chunks    |
| NO_PADDING flag                  | Done     | Skips padding when set             |

### Decoder Framework

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| ChunkDecoder lifecycle           | Done     | begin_decode / process_shard / end_decode |
| Deferred lifecycle (sharding)    | Done     | end_decode deferred until flush    |
| FormDecoder lifecycle            | Done     | begin / process_chunk / process_nested_form / end |
| Decoder registration (Factory)   | Done     | By IFF_Tag (form) or IFF_Chunk_Key (chunk) |
| Parser_State for decoder access  | Done     | FindProp delegates to session      |

### Directive System

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| ' IFF' (flags negotiation)       | Done     | Registered processor, UPDATE_FLAGS action |
| ' IFF' scope guards              | Done     | Size/tag widening, blobbed→progressive |
| ' END' (progressive termination) | Done     | Direct handling, size must be 0    |
| ' CHK' (start checksum span)    | Done     | Direct handling, delegates to Reader |
| ' SUM' (end checksum span)      | Done     | Direct handling, delegates to Reader |
| '    ' (shard / filler)          | Done     | SHARDING: dispatch to decoder; else filler |
| ' DEF' (segment identity)        | Done     | Read and skip via generic handler  |
| ' REF' (segment reference)       | Done     | Multi-option resolver, reader swap |
| ' VER' / ' REV'                  | Done     | Read and skip (non-normative)      |
| Unknown directives               | Done     | Forward-compat: read and skip      |
| Directive processor registry     | Done     | Extensible via Factory             |

### Segmentation & Inclusion

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| IFF_ReaderFrame (saved state)    | Done     | Stores reader, file_handle, iff85_locked |
| Reader stack (push/pop)          | Done     | Max depth 16 (circular inclusion guard) |
| SegmentSwitch state              | Done     | Exits Parse_Segment, Scan re-enters |
| parsing_resumed flag             | Done     | Prevents false IFF-85 bootstrap    |
| Segment resolver callback        | Done     | SetSegmentResolver API             |
| EOF during inclusion             | Done     | Pop reader stack, resume parent    |
| ' END' at global scope           | Done     | Pop reader stack, resume parent    |
| Deconstruct unwind               | Done     | Pops all frames before releasing root |
| ReadPayloadSize (exposed)        | Done     | Shared by CHK/SUM and REF parsing  |

### Checksum Infrastructure (DataTap layer)

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| DataTap_StartSpan                | Done     | Creates ChecksumSpan with calculators |
| DataTap_EndSpan                  | Done     | Finalize + compare, LIFO pop       |
| Transparent byte feeding         | Done     | UpdateAllSpans on every ReadRaw    |
| Skip with checksum awareness     | Done     | Reads bytes to feed calculators    |
| ChecksumAlgorithm vtable         | Done     | create_context/update/finalize/release |
| ChecksumCalculator               | Done     | Wraps algorithm + context          |
| ChecksumSpan (list of calcs)     | Done     | LIFO nesting support               |
| Algorithm registration           | Done     | IFF_DataTap_RegisterAlgorithm      |
| Reader StartChecksumSpan         | Done     | Parses CHK payload, builds VPS_Set |
| Reader EndChecksumSpan           | Done     | Parses SUM payload, verifies via DataTap |

### Checksum Algorithms

| Algorithm                        | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| LRC-ISO-1155                     | Done     | XOR of all bytes, 8-bit output     |
| RFC-1071                         | Done     | One's complement sum, 16-bit BE    |
| CRC-32C (Castagnoli)             | Done     | Reflected poly 0x82F63B78, 32-bit BE |
| CRC-64/ECMA-182                  | Done     | MSB-first poly 0x42F0E1EBA9EA3693, 64-bit BE |


3. Bootstrapping Behavior (Spec Section 9)
-------------------------------------------

The parser starts in pseudo IFF-85 mode (`IFF_HEADER_FLAGS_1985`, version 40
with all flags zeroed). This allows:

- If first tag is a container (FORM/LIST/CAT): implicit IFF-85 mode.
  The session sets `iff85_locked = 1`, rejecting all subsequent directives
  except `'    '` (filler).
- If first tag is ' IFF': explicit mode switch via directive processor.
  `iff85_locked` remains 0.

The session starts in `Idle`, transitions to `Segment` on first
`Parse_Segment` call, and ends in `Complete` on clean EOF or `Failed` on
error.


3b. Strict Container Validation
---------------------------------

When `STRICT_CONTAINERS` is set (Structuring Bit 2), `Parse_Container_FORM`
checks whether the parent scope is a CAT or LIST with a non-wildcard type.
If so, the FORM's type must match the parent's declared type or parsing
fails with return 0.


4. Writer / Generator Implementation Status
--------------------------------------------

### Write-Side Decorator Stack

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

### VulpesCore Write Support

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| VPS_Endian write functions       | Done     | Write16/32/64 UBE/ULE             |
| VPS_DataWriter                   | Done     | Sequential writes into VPS_Data    |
| VPS_StreamWriter                 | Done     | Buffered file output via write()   |

### Write Stack

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| IFF_WritePump                    | Done     | Wraps VPS_StreamWriter             |
| IFF_WriteTap                     | Done     | Checksum accumulation on writes    |
| IFF_Writer                       | Done     | Tag/size/data serialization        |
| IFF_WriteScope                   | Done     | Per-container write state          |

### Generator (Imperative API)

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| BeginForm / EndForm              | Done     | Progressive and blobbed modes      |
| BeginList / EndList              | Done     | Progressive and blobbed modes      |
| BeginCat / EndCat                | Done     | Progressive and blobbed modes      |
| BeginProp / EndProp              | Done     | Subcontainer lifecycle             |
| WriteChunk                       | Done     | Tag + size + data + padding        |
| WriteHeader (' IFF')             | Done     | Flags negotiation for output       |
| WriteDEF (' DEF')                | Done     | Segment identity                   |
| WriteREF (' REF')                | Done     | Segment references                 |
| WriteFiller ('    ')             | Done     | Zero-filled alignment padding      |
| WriteShard ('    ')              | Done     | Continuation data (requires SHARDING) |
| WriteVER (' VER')               | Done     | Version directive                  |
| WriteREV (' REV')               | Done     | Revision directive                 |
| BeginChecksumSpan (' CHK')       | Done     | Progressive + blobbed modes        |
| EndChecksumSpan (' SUM')         | Done     | Progressive + blobbed modes        |
| Progressive mode (END-terminated)| Done     | Streaming-friendly output          |
| Blobbed mode (accumulate-write)  | Done     | Non-seekable fd support            |
| Nested blobbed containers        | Done     | Arbitrary depth                    |
| Content-type validation           | Done     | FORM/PROP chunks, LIST/CAT containers |
| STRICT_CONTAINERS validation     | Done     | CAT/LIST type vs child type matching |
| WriteHeader scope validation     | Done     | Rejects if inside a container      |
| bytes_written tracking           | Done     | All chunks + directives on scope   |
| Flush                            | Done     | Validates no open scopes/spans     |

### Encoder Framework

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| IFF_ChunkEncoder vtable          | Done     | encode() produces raw data         |
| IFF_FormEncoder vtable           | Done     | begin/produce_chunk/produce_nested/end |
| IFF_Generator_State              | Done     | Encoder-facing view                |
| IFF_Generator_Factory            | Done     | Builder pattern, creates configured generators |
| Factory-driven EncodeForm        | Done     | Recursive form encoding            |


5. Compilation
--------------

All source files compile cleanly with MinGW GCC 13.1 (C23, `-std=gnu2x`).
Pre-existing warnings in `IFF_ChecksumAlgorithm.h` and `IFF_DataTap.h`
(forward declarations inside parameter lists) are cosmetic and do not affect
correctness.

Toolchain: CLion 2024.3.5 bundled MinGW, Ninja generator.
