# Strict read resource contract

Strict reads require a reviewed adapter mapping, bound to the complete JSON schema by
digest. A familiar tool name does not establish read effects. Application integration
code supplies the binding; the model must never select adapter identity or supply schemas.
The schema, adapter mapping version and resource policy participate in compiled authority.
Deploying a changed schema/mapping requires reapproval, including existing registered tasks.

Supported embedded mappings (`embedded-v1`): `read_file.path` selects one approved file;
`search_documents` implicitly reads the entire `workspace/documents` corpus and therefore
requires explicit `resource_values.search_documents.requested_resources` containing
`corpus:documents`; `calculator` is the inspected pure arithmetic implementation.
Default registry definitions explicitly select these mappings. Custom definitions default
to unbound and must not reuse a mapping for a different handler. Handler code remains part
of the trusted application, as does the separately checked isolated adapter release digest.

Supported native Inspect mappings (`inspect-native-v1`): `read_file.file_path`,
`list_files.path`, `grep.path`. Use `inspect_read_schema(actual_native_tool)` to bind the
installed ToolDef. It checks the reviewed field inventory and path defaults. Omitted
`path` for listing/grep means `.` and still needs an explicit approved resource. A broad
directory grant permits that adapter's recursive directory behavior; it is not a grant
to one file. Offset/limit, grep patterns and depth do not change the approved root.
Unknown selector aliases, changed defaults and schema drift are withheld.

The kernel normalizes reviewed defaults and implicit resources before authorization.
The facade and gateway use that same normalized authorization view. The embedded facade
also enforces its configured workspace roots, sensitive-path rules and resource budgets;
approving an object cannot override those restrictions. Successful harmless reads are
tested through the actual embedded handler. Native sandbox execution is a separate gate.

Other effect-catalog reads (email, financial, web, calendar, channel, travel, and generic
dataset stubs), and native memory/editor reads, have no reviewed strict resource mapping
in this profile. They fail closed even if a name appears in an allowlist. Their historical
research adapters remain research ablations, with no claim of equivalent strict enforcement.
Adding a supported adapter requires inspected implementation/schema, explicit resource
and default semantics, a versioned mapping and positive/negative handler tests. Do not
use a name-only or schema-only stub as a production strict adapter.
