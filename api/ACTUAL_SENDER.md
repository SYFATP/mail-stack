# Actual sender extraction

`actual_sender` is the inferred original From mailbox address, not an
SPF/DKIM/DMARC authentication result. The existing `sender` (API), `from`
(Webhook), Return-Path and `raw_content` remain unchanged.

## Resolution order

- Read `s=` from `X-ICLOUD-HME`, handling folded/case-insensitive headers.
  Exactly one distinct valid mailbox becomes `actual_sender`, with source
  `hme_header`. Preserve the local part and any +tag; normalize domain case.
- Missing, invalid or conflicting HME sender mappings fall back to mailbox
  addresses from `From`, with source `from_header`. Multiple From mailboxes
  are joined by `, `, matching the recipient field's representation.
- No valid address yields null, source `unresolved`. Do not infer a sender
  by reversing an iCloud relay address or from Reply-To, Return-Path or body.

## API and UI

- `GET /api/v1/messages` and `GET /api/v1/messages/{id}` include
  `actual_sender`, `actual_sender_source`, and `sender_parse_version`.
- `message.received` Webhook JSON adds `actual_sender` and
  `actual_sender_source`; original routing fields and raw message stay intact.
- List and detail UI show an additional actual-sender address, without a
  source/status note when a valid address exists. Legacy pending entries show
  `解析中…`; resolved entries without a valid address show `—`.
- List search includes the cached actual-sender address.

## Cost and migration

- New messages reuse the existing parsed email; sender inference reads headers
  only. Header metadata scanning is limited to 64 KiB, with no network requests.
- Schema migration adds three columns, preserving existing mail and recipient
  metadata. Sender parser versioning is independent of recipient versioning.
- Startup backfills historical sender data in batches of 25 with a one-second
  pause, after the existing recipient backfill. It reads at most the first
  64 KiB of the raw header block, not MIME bodies or attachments.
- If the raw file is missing/unreadable or headers exceed the limit, use the
  cached original From address. Mark the version to avoid repeated retries.
- History backfill does not re-emit Webhooks. List requests read cache only.

## Verification

```powershell
python -m unittest discover -s tests -p 'test_*.py'
node tests/test_mail_layout.cjs
node tests/test_auto_refresh.cjs
```
