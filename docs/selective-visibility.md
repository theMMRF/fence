# Authenticated IndexD resolution

Set `INDEXD_AUTHENTICATED_READS: true` in the existing Fence configuration when
using an IndexD deployment with restricted discovery. It defaults to false.
`INDEXD_USERNAME` and `INDEXD_PASSWORD` must be present in Fence's server secret;
missing credentials fail closed. IndexD GET requests then use those trusted
service credentials and disable redirects so credentials cannot follow a record
resolution redirect to another service.

Fence needs the record before its existing storage checks, including write-only
upload grants and verified passport downloads. Resolving it with the service
identity does not authorize the caller to download. `IndexedFile.get_signed_url`
still checks read-storage on all authz resources before signing; restricted
records denied that check return a generic 404. Delete denials are also masked.
No endpoint, SDK download contract, or URL signer has been replaced.

This patch is based on **13.1.0**, the image selected in MMRF production GitOps,
not a newer upstream master. Its review base is `mmrf/13.1.0` in the MMRF fork.
Do not merge it as a rollback of upstream master. Promote it alongside IndexD,
search filtering, prepared metadata and the reviewed SDK/client revisions.

Run `pytest tests/data/test_indexd_visibility.py tests/data/test_indexed_file.py`
with the normal test configuration and a disposable local Postgres database.
The tests mock cloud storage and include allowed and denied restricted downloads.
