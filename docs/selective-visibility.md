# Authenticated IndexD resolution

Set `INDEXD_AUTHENTICATED_READS: true` in the existing Fence configuration when
using an IndexD deployment with restricted discovery. It defaults to false.
`INDEXD_USERNAME` and `INDEXD_PASSWORD` must be present in Fence's server secret;
missing credentials fail closed. IndexD GET requests then use those trusted
service credentials and disable redirects so credentials cannot follow a record
resolution redirect to another service. Both IndexD GET paths have a finite
30-second timeout, including when the feature is disabled.

Fence needs the record before its existing storage checks, including write-only
upload grants and verified passport downloads. Resolving it with the service
identity does not authorize the caller to download. `IndexedFile.get_signed_url`
still checks `fence/read-storage` on all authz resources before signing;
`indexd/read-metadata` grants discovery independently and does not authorize
storage. A downloader need not have discovery permission to use an already-known
GUID: the trusted service lookup deliberately allows that case. Restricted
records denied that check return a generic 404. Delete denials are also masked.
No endpoint, SDK download contract, or URL signer has been replaced.

This patch retains the source of the dev **2026.10** Fence image, verified from
its linux/amd64 OCI label: `9c5a51155450768fc32cb89c88dd2aea9eddc0f3`
(application version 13.3.0). Its review base is `mmrf/2026.10` in the MMRF fork.
The feature branch keeps its original `-13.1` name to preserve the existing PR;
that name no longer describes its build baseline. Promote it alongside IndexD,
search filtering, prepared metadata and the reviewed SDK/client revisions.

Run `pytest tests/data/test_indexd_visibility.py tests/data/test_indexed_file.py`
with the normal test configuration and a disposable local Postgres database.
The tests mock cloud storage and include allowed and denied restricted downloads.
