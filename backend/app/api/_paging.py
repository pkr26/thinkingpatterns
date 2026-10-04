"""Shared metadata-first pagination for encrypted collections.

Callers size rows before fetching ciphertext and read the collection
revision before and after the fetch. A changed revision produces a retryable
409 collection_changed response.

Clients opt into short pages with page_bytes and follow X-Next-Offset. Legacy
requests must fit their full requested page within the hard response budget
or receive 413. An oversized first row also produces 413, avoiding an empty
page that could look complete. Continuations are emitted only when a page
returned rows and more history remains.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from fastapi import Response

from ..deps import ApiError

# The continuation header every byte-paginating client follows.
NEXT_OFFSET_HEADER = "X-Next-Offset"

# Revision values travel in an HTTP header and optional query parameter.  Keep
# their grammar canonical and bounded to the signed 64-bit database column:
# this rejects parser-friendly but framing-ambiguous forms such as ``+1``,
# ``01``, whitespace, and Unicode digits.
MAX_COLLECTION_REVISION = 2**63 - 1
_EXPECTED_REVISION_RE = re.compile(r"(?:0|[1-9][0-9]{0,18})")


def parse_expected_revision(value: str | None) -> int | None:
    """Parse a client snapshot marker without accepting permissive int forms."""
    if value is None:
        return None
    if not isinstance(value, str) or _EXPECTED_REVISION_RE.fullmatch(value) is None:
        raise ApiError(
            status_code=422,
            detail="expected_revision must be a canonical non-negative decimal",
            code="validation_error",
        )
    revision = int(value)
    if revision > MAX_COLLECTION_REVISION:
        raise ApiError(
            status_code=422,
            detail="expected_revision must be a canonical non-negative decimal",
            code="validation_error",
        )
    return revision


def collection_changed_error(
    collection: str, header_name: str, current_revision: int | None = None
) -> ApiError:
    """Ask the client to restart paging with the current snapshot marker."""
    headers = {header_name: str(current_revision)} if current_revision is not None else None
    return ApiError(
        status_code=409,
        detail=f"{collection} changed while paging; retry the request",
        code="collection_changed",
        headers=headers,
    )


def assert_expected_revision(
    expected_revision: int | None,
    current_revision: int,
    *,
    collection: str,
    header_name: str,
) -> None:
    if expected_revision is not None and expected_revision != current_revision:
        raise collection_changed_error(collection, header_name, current_revision)


@dataclass(frozen=True)
class BytePage:
    """The ids selected for this page plus whether more history exists."""

    selected: list[tuple[str, int]]
    has_more: bool


def select_byte_page(
    requested: Sequence[tuple[str, int]],
    *,
    more_after_request: bool,
    page_bytes: int | None,
    hard_budget: int,
    collection: str,
) -> BytePage:
    """Choose the rows that fit this page's byte budget (metadata only).

    ``requested`` is the (id, byte-length) metadata page the caller already
    loaded (WITHOUT the limit+1 evidence row); ``more_after_request`` says
    whether that extra row existed.
    """
    if page_bytes is None:
        total = sum(size for _, size in requested)
        if total > hard_budget:
            raise ApiError(
                status_code=413,
                detail=(
                    f"requested {collection} page exceeds the "
                    f"{hard_budget // (1024 * 1024)} MiB ciphertext budget; "
                    "upgrade to a byte-paginating client"
                ),
                code="payload_too_large",
            )
        return BytePage(list(requested), more_after_request)
    selected: list[tuple[str, int]] = []
    used = 0
    for row_id, size in requested:
        if size > page_bytes:
            if not selected:
                raise ApiError(
                    status_code=413,
                    detail=f"an item in this {collection} page exceeds the requested page byte budget",
                    code="payload_too_large",
                )
            break
        if used + size > page_bytes:
            break
        selected.append((row_id, size))
        used += size
    truncated = len(selected) < len(requested)
    return BytePage(selected, more_after_request or truncated)


def verify_fetched_page(
    selected_ids: Sequence[str],
    fetched: Sequence,
    *,
    byte_limit: int,
    collection: str,
    header_name: str,
    revision: int,
) -> list:
    """Order the fetched rows to the selection and refuse a page that moved.

    A missing id or a grown blob total means the collection changed between
    the metadata sizing pass and the blob fetch — retryable 409
    collection_changed, never a short page a legacy client mistakes for
    complete history. Rows must expose ``.id`` and ``.blob``.
    """
    rows_by_id = {row.id: row for row in fetched}
    if len(rows_by_id) != len(selected_ids):
        raise collection_changed_error(collection, header_name, revision)
    ordered = [rows_by_id[row_id] for row_id in selected_ids]
    if sum(len(bytes(row.blob)) for row in ordered) > byte_limit:
        raise collection_changed_error(collection, header_name, revision)
    return ordered


def emit_page_headers(
    response: Response,
    *,
    revision: int,
    header_name: str,
    has_more: bool,
    rows_returned: int,
    offset: int,
) -> None:
    """Stamp the snapshot marker and (guarded) continuation header.

    The revision header is set on EVERY successful page — including empty
    and terminal pages — so a client never needs to infer the snapshot from
    a continuation header. The continuation is emitted only when history
    remains AND rows were returned (the non-advancing guard; see module
    docs), and advances by exactly the number of rows the caller received.
    """
    response.headers[header_name] = str(revision)
    if has_more and rows_returned > 0:
        response.headers[NEXT_OFFSET_HEADER] = str(offset + rows_returned)
