IFF-2025 Spec Compliance Gaps
=============================

Last updated: 2026-03-15 (all gaps resolved, conformance testing complete)

All IFF-2025 specification features are implemented on both read and write
paths. The conformance test suite (204 test functions, 210 conformance points)
provides full coverage.


Previously Open Gaps (All Resolved)
-------------------------------------

1. CHK/SUM integrity spans -- Resolved (Feb 2026)
2. Checksum algorithm implementations -- Resolved (Feb 2026)
3. Sharding ('    ' directive) -- Resolved (Feb 2026)
4. Strict container validation -- Resolved (Feb 2026)
5. Scope guards (child vs parent flags) -- Resolved (Feb 2026)
6. IFF-85 mode locking -- Resolved (Feb 2026)
7. DEF/REF segmentation & inclusion -- Resolved (Feb 2026)

See `documentation/status.md` Section 4 for details on each resolution.


Bugs Found by Conformance Testing (All Fixed)
-----------------------------------------------

These bugs were discovered during conformance test development (Mar 2026)
and fixed immediately:

1. **Container type tag misclassification** -- `ReadTag` classified wildcard
   container type identifiers as `DIRECTIVE` instead of `TAG`, breaking
   `STRICT_CONTAINERS` wildcard parent matching.
   *Files*: `src/IFF_Parser.c`

2. **Progressive checksum span mismatch** -- Generator's progressive-mode
   `EndChecksumSpan` did not feed `' SUM'` tag bytes to the WriteTap
   calculators before finalizing, causing checksum verification failure on
   parse. The blobbed path had this compensation; the progressive path was
   missing it.
   *Files*: `src/IFF_Generator.c`

3. **All 4 production checksum algorithm finalize functions broken** --
   `LRC_Finalize`, `RFC1071_Finalize`, `CRC32C_Finalize`, and
   `CRC64_Finalize` all called `VPS_Data_Resize` on a `VPS_Data` allocated
   with `(0, 0)` which has `own_bytes=0`. `Resize` silently rejected the
   operation. Only the test-only `TEST-XOR` algorithm worked (it manually
   allocated the buffer).
   *Files*: `src/IFF_Checksum_LRC.c`, `src/IFF_Checksum_RFC1071.c`,
   `src/IFF_Checksum_CRC32C.c`, `src/IFF_Checksum_CRC64ECMA.c`


Features Added During Conformance Testing
-------------------------------------------

1. **IFF header version validation** -- The `' IFF'` processor now validates
   the version field: `0` locks to IFF-85, `40` is IFF-2025, anything else
   halts parsing. New action: `IFF_ACTION_LOCK_IFF85`.
   *Files*: `src/IFF_Directive_IFF_Processor.c`, `include/IFF/IFF_DirectiveResult.h`,
   `src/IFF_Parser.c`

2. **Strict references mode** -- `parser->strict_references = 1` causes
   mandatory `' REF'` directives to fail when no resolver is registered.
   Default is forward-compatible (silently consume).
   *Files*: `include/IFF/IFF_Parser.h`, `src/IFF_Parser.c`
