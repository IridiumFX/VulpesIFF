VulpesIFF Implementation Status
================================

Last updated: 2026-03-15 (conformance tests complete, all production bugs fixed)


1. Architecture Overview
------------------------

The implementation follows a layered decorator pattern for both read and
write paths:

```
Read Path                          Write Path
─────────                          ──────────
IFF_Parser                         IFF_Generator
    │                                  │
IFF_Reader                         IFF_Writer
    │                                  │
IFF_DataTap                        IFF_WriteTap
    │                                  │
IFF_DataPump                       IFF_WritePump
    │                                  │
File / Socket                      File / Socket
```

Supporting infrastructure:

- **IFF_Parser_Session** -- Scope stack (VPS_List), active scope pointer,
  session state machine, PROP storage (VPS_ScopedDictionary).
- **IFF_Parser_State** -- Decoder-facing view into the session; exposes
  `FindProp` without coupling decoders to session internals.
- **IFF_Parser_Factory** -- Builder that owns decoder/processor registries
  (VPS_Dictionary) and constructs configured Parser instances.
- **IFF_Scope** -- Per-container state: flags, boundary, variant/type tags,
  active FormDecoder + its custom state, shard tracking fields.
- **IFF_Boundary** -- Tracks `level` (bytes consumed) against `limit`
  (declared container size, or 0 for unbounded/progressive).


2. Feature Status
-----------------

All IFF-2025 spec features are implemented on both read and write paths.

### Core Parser

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| Parse_Segment (top-level loop)   | Done     | Handles IFF/container dispatch     |
| Parse_Container_FORM             | Done     | Size, type validation, scope, decoder lifecycle |
| Parse_Container_LIST             | Done     | PROP + container nesting           |
| Parse_Container_CAT              | Done     | Container-only nesting             |
| Parse_PROP                       | Done     | Flat chunks, PROP storage via ScopedDictionary |
| Parse_Chunk                      | Done     | Decoder lookup, raw fallback, PROP/FORM routing |
| Parse_Directive                  | Done     | All directives handled             |
| HandleSegmentRef (' REF')        | Done     | Multi-option resolver, reader swap |
| IFF_Parser_Scan (entry point)    | Done     | Loops segments until Complete/Failed/SegmentSwitch |

### Tag System

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| 4/8/16-byte tag reading          | Done     | Via IFF_Header_Flags_GetTagLength  |
| Canonical normalization          | Done     | Right-pad data, left-pad directive |
| Type classification              | Done     | TAG, CONTAINER, SUBCONTAINER, DIRECTIVE |
| Container reclassification       | Done     | Post-construct memcmp against FORM/LIST/CAT/PROP |
| Container type tag reclassification | Done  | Force type tags to TAG after ReadTag |
| Tag comparison + hashing         | Done     | FNV-1a on type + canonical data    |

### Directive System

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| ' IFF' (flags negotiation)       | Done     | Registered processor, UPDATE_FLAGS action |
| ' IFF' version validation        | Done     | version=0 locks IFF-85, unknown versions fail |
| ' IFF' scope guards              | Done     | Size/tag widening, blobbed->progressive |
| ' END' (progressive termination) | Done     | Direct handling, size must be 0    |
| ' CHK' (start checksum span)    | Done     | Direct handling, delegates to Reader |
| ' SUM' (end checksum span)      | Done     | Direct handling, delegates to Reader |
| '    ' (shard / filler)          | Done     | SHARDING: dispatch to decoder; else filler |
| ' DEF' (segment identity)        | Done     | Read and skip via generic handler  |
| ' REF' (segment reference)       | Done     | Multi-option resolver, strict_references mode |
| ' VER' / ' REV'                  | Done     | Read and skip (non-normative)      |
| Unknown directives               | Done     | Forward-compat: read and skip      |

### Generator (Imperative API)

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| BeginForm / EndForm              | Done     | Progressive and blobbed modes      |
| BeginList / EndList              | Done     | Progressive and blobbed modes      |
| BeginCat / EndCat                | Done     | Progressive and blobbed modes      |
| BeginProp / EndProp              | Done     | Subcontainer lifecycle             |
| WriteChunk                       | Done     | Tag + size + data + padding        |
| WriteHeader (' IFF')             | Done     | Flags negotiation for output       |
| WriteDEF / WriteREF              | Done     | Segment identity and references    |
| WriteFiller / WriteShard         | Done     | Filler and shard directives        |
| WriteVER / WriteREV              | Done     | Version and revision directives    |
| BeginChecksumSpan / EndChecksumSpan | Done  | Progressive + blobbed modes        |
| Content-type validation          | Done     | FORM/PROP chunks, LIST/CAT containers |
| STRICT_CONTAINERS validation     | Done     | CAT/LIST type vs child type matching |
| bytes_written tracking           | Done     | All chunks + directives on scope   |
| Flush                            | Done     | Validates no open scopes/spans     |

### Encoder / Decoder Framework

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| ChunkDecoder lifecycle           | Done     | begin_decode / process_shard / end_decode |
| Deferred lifecycle (sharding)    | Done     | end_decode deferred until flush    |
| FormDecoder lifecycle            | Done     | begin / process_chunk / process_nested_form / end |
| ChunkEncoder vtable              | Done     | encode() produces raw data         |
| FormEncoder vtable               | Done     | begin/produce_chunk/produce_nested/end |
| Factory-driven EncodeForm        | Done     | Recursive form encoding            |

### Checksum Algorithms

| Algorithm                        | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| LRC-ISO-1155                     | Done     | XOR of all bytes, 8-bit output     |
| RFC-1071                         | Done     | One's complement sum, 16-bit BE    |
| CRC-32C (Castagnoli)             | Done     | Reflected poly 0x82F63B78, 32-bit BE |
| CRC-64/ECMA-182                  | Done     | MSB-first poly 0x42F0E1EBA9EA3693, 64-bit BE |

### Segmentation & Inclusion

| Feature                          | Status   | Notes                              |
|----------------------------------|----------|------------------------------------|
| IFF_ReaderFrame (saved state)    | Done     | Stores reader, file_handle, iff85_locked |
| Reader stack (push/pop)          | Done     | Max depth 16 (circular inclusion guard) |
| Segment resolver callback        | Done     | SetSegmentResolver API             |
| strict_references mode           | Done     | Mandatory REF fails without resolver when enabled |


3. Conformance Testing
-----------------------

204 test functions verify 210 conformance points from the IFF-2025
conformance matrix (see `documentation/conformance-tests.md`).

| Path       | Conformance Points | Test Functions | Multi-coverage |
|------------|--------------------|----------------|----------------|
| Read (R)   | 108                | 103            | 5              |
| Write (W)  | 102                | 101            | 4              |
| **Total**  | **210**            | **204**        | **9**          |

Tests are organized across 40 suites covering: bootstrapping, header flags,
containers, chunks, directives, mid-stream IFF, scope guards, boundary
validation, flag combinations, PROP resolution, decoder lifecycle, sharding,
checksum algorithms, checksum spans, generator validation, encoder framework,
bytes_written tracking, version handling, and round-trip symmetry.

Test binary: `cmake-build-debug/Tests/VulpesIFF_Tests.exe`
Build target: `VulpesIFF_Tests`


4. Bugs Found and Fixed by Conformance Testing
------------------------------------------------

### Bug 1: Container type tag misclassification

`IFF_Reader_ReadTag` classified all-space type identifiers (wildcard `"    "`)
as `IFF_TAG_TYPE_DIRECTIVE` because `bytes[0] == ' '`. This caused
`IFF_Tag_Compare` to report wildcard container types as unequal to
`IFF_TAG_SYSTEM_WILDCARD` (which has type `TAG`), breaking `STRICT_CONTAINERS`
wildcard parent matching.

**Fix**: After calling `ReadTag` for container type tags in all four container
handlers (FORM, LIST, CAT, PROP), force `type = IFF_TAG_TYPE_TAG`. Type tags
are content identifiers, not structural markers.

**Files**: `src/IFF_Parser.c` (4 locations)

### Bug 2: Progressive checksum span SUM tag mismatch

In progressive mode, `IFF_Generator_EndChecksumSpan` called
`IFF_WriteTap_EndSpan` without first feeding the `' SUM'` tag bytes to the
active calculators. The parser's `DataTap` reads the SUM tag through the tap
(feeding it to calculators) before pausing the span, so the computed checksums
diverged. The blobbed path already had compensation code for this; the
progressive path was missing it.

**Fix**: Before calling `WriteTap_EndSpan`, manually feed the SUM tag bytes
to all active span calculators, mirroring the blobbed path's approach.

**Files**: `src/IFF_Generator.c` (EndChecksumSpan progressive branch)

### Bug 3: All 4 production checksum algorithm finalize functions broken

All production algorithms (LRC, RFC-1071, CRC-32C, CRC-64/ECMA) called
`VPS_Data_Resize` in their `finalize` callbacks. But the caller
(`WriteTap_EndSpan` / `DataTap_EndSpan`) allocates the output `VPS_Data` with
`VPS_Data_Allocate(&data, 0, 0)`, which leaves `own_bytes = 0`. `Resize`
rejects buffers it doesn't own, so all four finalize functions silently failed.
The TEST-XOR algorithm worked because it manually allocated the buffer
(with a comment explaining why).

**Fix**: Replaced `VPS_Data_Resize` with direct `calloc` + manual field
assignment in all four algorithm finalize functions.

**Files**: `src/IFF_Checksum_LRC.c`, `src/IFF_Checksum_RFC1071.c`,
`src/IFF_Checksum_CRC32C.c`, `src/IFF_Checksum_CRC64ECMA.c`


5. Features Added During Conformance Testing
----------------------------------------------

### IFF header version validation

The `' IFF'` directive processor now validates the version field:
- `version = 0` (IFF-85): Returns `IFF_ACTION_LOCK_IFF85`, locking the
  session to IFF-85 mode with default flags.
- `version = 40` (IFF-2025): Proceeds normally.
- Any other version: Returns `IFF_ACTION_HALT` with
  `IFF_ERROR_UNSUPPORTED_FEATURE`.

**Files**: `src/IFF_Directive_IFF_Processor.c`,
`include/IFF/IFF_DirectiveResult.h` (new `IFF_ACTION_LOCK_IFF85` action),
`src/IFF_Parser.c` (handler for new action)

### Strict references mode

Added `strict_references` field to `IFF_Parser`. When enabled, mandatory
`' REF'` directives (those with `id_size > 0`) cause parse failure if no
segment resolver is registered. Default is `0` (forward-compatible: silently
consume all unresolved references).

**Files**: `include/IFF/IFF_Parser.h`, `src/IFF_Parser.c`
(HandleSegmentRef)


6. Compilation
--------------

All source files compile cleanly with MinGW GCC 13.1 (C23, `-std=gnu2x`).
Pre-existing warnings in `IFF_ChecksumAlgorithm.h` and `IFF_DataTap.h`
(forward declarations inside parameter lists) are cosmetic and do not affect
correctness.

Toolchain: CLion 2024.3.5 bundled MinGW, Ninja generator.


7. Documentation
-----------------

| Document                                  | Location                          |
|-------------------------------------------|-----------------------------------|
| IFF-2025 Specification                    | `IFF-2025/Docs/IFF-2025.md`      |
| IFF-2025 Implementor's Guide             | `IFF-2025/Docs/IFF-2025-implementors-guide.md` |
| VulpesIFF Integration Guide              | `documentation/VulpesIFF-Integration-Guide.md` |
| Conformance Test Matrix                  | `documentation/conformance-tests.md` |
| Write-Side Architecture                  | `documentation/architecture-writer.md` |
| This File                                | `documentation/status.md`         |
