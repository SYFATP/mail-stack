# Actual recipient extraction

`actual_recipient` is an inferred original destination, not an authentication result.
The existing `envelope_recipient`, `to`, `to_addr`, `original_to` (the literal
`X-Original-To` header), and `raw_content` retain their original meanings.

## Resolution order

- For exactly one `X-ICLOUD-HME` `p` address, prefer its complete tagged address,
  or a matching `alias+tag=domain` / `alias+tag@domain` in `To`, `Received-SPF`,
  `Authentication-Results`, or `Return-Path`.
- If no matching header candidate exists, scan inline text/plain or text/html
  bodies for `login_hint`; decode MIME transfer encoding, HTML entities and up
  to two percent-encoding layers. Literal `+` is preserved.
- Candidates must match the HME alias local-part and domain. Conflicting
  candidates fall back to the HME alias rather than choosing an arbitrary tag.
- No complete candidate: return `p`, source `hme_alias`. This indicates that
  no full `+tag` was found, not that the alias is invalid.
- Ordinary mail: use the `To` mailbox address(es), then the envelope recipient.
  Missing addresses produce null, source `unresolved`.

`actual_recipient_source` is one of `hme_header`, `hme_login_hint`, `hme_alias`,
`to_header`, `envelope_recipient`, or `unresolved`.

## Cost and compatibility

- New mail reuses the existing parsed message and stores the result during the
  same database insert. Webhooks receive these two additional fields alongside
  the untouched raw email and original routing fields.
- Header candidate scanning is capped at 64 KiB. Body fallback is capped at
  1 MiB of decoded text and 100 MIME nodes. Attachments, nested attached emails,
  and individual encoded bodies over 2 MiB are skipped. No network fetches,
  tracking links, DNS lookups, or cryptographic verification are performed.
- A versioned startup background worker backfills existing messages newest
  first in batches of 25, with a one-second pause between batches. It does not
  re-emit old webhooks. Database columns migrate automatically.
- List/search requests read cached database values only. Search includes the
  complete actual recipient. While history is pending, the UI shows `解析中…`.
- Tagged and untagged HME addresses are both displayed as ordinary mailbox
  addresses, without a missing-tag notice. The source remains available in API
  metadata for diagnosis.
- Missing/unreadable historical raw files are marked unresolved for this parser
  version, rather than repeatedly reading them on each list refresh.

## Verification

```powershell
python -m unittest discover -s tests -p test_actual_recipient.py
python -m unittest discover -s tests -p test_webhook_auth.py
node tests/test_mail_layout.cjs
node tests/test_auto_refresh.cjs
```

Deploy both `mail-api` and `mail-frontend` to enable the new API fields and column.
Keep a database backup before deploying migrations. Rolling back the previous
application code can ignore the additional columns.
