"""Durable audit anchors, consent evidence, and privacy attestations."""

import uuid

import sqlalchemy as sa
from alembic import op

revision = "e1b7c9d3a5f2"
down_revision = "d6a0c4e8b213"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for owner_column in ("user_id", "therapist_id"):
        overflow = bind.execute(
            sa.text(
                f"""SELECT {owner_column}
                       FROM consents
                      GROUP BY {owner_column}
                     HAVING COUNT(*) > 1000
                      LIMIT 1"""  # noqa: S608 - closed migration identifiers
            )
        ).first()
        if overflow is not None:
            raise RuntimeError(
                "retained sharing history exceeds the supported 1000-row migration limit"
            )
    op.add_column(
        "users",
        sa.Column(
            "consents_revision", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "patients_revision", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
    )
    op.add_column("users", sa.Column("age_attestation_version", sa.String(32), nullable=True))
    op.add_column("users", sa.Column("age_attested_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "account_deletion_tombstones",
        sa.Column("user_id", sa.String(32), primary_key=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("token_epoch", sa.BigInteger(), nullable=False),
        sa.Column("auth_secret_version", sa.Integer(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("record_mac", sa.String(64), nullable=False),
    )
    op.create_index(
        "ix_account_deletion_tombstones_expiry",
        "account_deletion_tombstones",
        ["expires_at"],
    )
    op.create_table(
        "account_deletion_jobs",
        sa.Column("user_id", sa.String(32), primary_key=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column(
            "phase",
            sa.String(32),
            server_default=sa.text("'note_revisions'"),
            nullable=False,
        ),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_account_deletion_jobs_requested",
        "account_deletion_jobs",
        ["requested_at"],
    )
    op.create_index(
        "ix_account_deletion_jobs_phase",
        "account_deletion_jobs",
        ["phase"],
    )
    op.create_index(
        "ix_account_deletion_jobs_updated",
        "account_deletion_jobs",
        ["updated_at", "user_id"],
    )
    # Account erasure walks these owner dimensions in fixed pages. They are
    # not leading columns of the pre-existing read-path indexes.
    op.create_index("ix_pairing_codes_therapist_id", "pairing_codes", ["therapist_id"])
    op.create_index("ix_notes_user_id", "therapist_notes", ["user_id"])
    op.create_index(
        "ix_note_revisions_therapist_id",
        "therapist_note_revisions",
        ["therapist_id"],
    )

    op.create_table(
        "consent_events",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("disclosure", sa.String(64), nullable=True),
        sa.Column("policy", sa.String(64), nullable=True),
        sa.Column("consent_id", sa.String(32), nullable=True),
        sa.Column("share_voice", sa.Boolean(), nullable=True),
        sa.Column("event_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_consent_events_user_at", "consent_events", ["user_id", "occurred_at"])
    consent_insert = sa.text(
        """INSERT INTO consent_events
           (id, user_id, kind, action, disclosure, policy, consent_id,
            share_voice, event_version, occurred_at)
           VALUES (:id, :user_id, :kind, :action, :disclosure, :policy,
                   :consent_id, :share_voice, 1, :occurred_at)"""
    )
    # Backfill in bounded user pages and cap each subject below the runtime
    # hard ceiling.  The remaining 202 slots are reserved for withdrawals
    # of permissions that were active when the migration completed.
    permission_ceiling = 9_798
    user_after = ""
    while True:
        user_rows = list(
            bind.execute(
                sa.text(
                    """SELECT id, llm_consent_at, llm_consent_disclosure,
                              llm_consent_policy, voice_consent_at,
                              voice_consent_disclosure, voice_consent_policy
                         FROM users
                        WHERE id > :after
                        ORDER BY id
                        LIMIT 500"""
                ),
                {"after": user_after},
            ).mappings()
        )
        if not user_rows:
            break
        for user_row in user_rows:
            inserted = 0
            for kind in ("llm", "voice"):
                occurred = user_row[f"{kind}_consent_at"]
                if occurred is None:
                    continue
                bind.execute(
                    consent_insert,
                    {
                        "id": uuid.uuid4().hex,
                        "user_id": user_row["id"],
                        "kind": kind,
                        "action": "granted",
                        "disclosure": user_row[f"{kind}_consent_disclosure"],
                        "policy": user_row[f"{kind}_consent_policy"],
                        "consent_id": None,
                        "share_voice": None,
                        "occurred_at": occurred,
                    },
                )
                inserted += 1
            consent_rows = bind.execute(
                sa.text(
                    """SELECT id, status, granted_at, revoked_at,
                              disclosure, share_voice
                         FROM consents
                        WHERE user_id = :user_id
                        ORDER BY granted_at DESC, id DESC
                        LIMIT :row_limit"""
                ),
                {
                    "user_id": user_row["id"],
                    "row_limit": permission_ceiling - inserted,
                },
            ).mappings()
            for row in consent_rows:
                needed = 2 if row["status"] == "revoked" and row["revoked_at"] else 1
                if inserted + needed > permission_ceiling:
                    break
                bind.execute(
                    consent_insert,
                    {
                        "id": uuid.uuid4().hex,
                        "user_id": user_row["id"],
                        "kind": "sharing",
                        "action": "granted",
                        "disclosure": row["disclosure"],
                        "policy": None,
                        "consent_id": row["id"],
                        # Legacy rows cannot prove when voice was toggled.
                        "share_voice": None,
                        "occurred_at": row["granted_at"],
                    },
                )
                inserted += 1
                if needed == 2:
                    bind.execute(
                        consent_insert,
                        {
                            "id": uuid.uuid4().hex,
                            "user_id": user_row["id"],
                            "kind": "sharing",
                            "action": "withdrawn",
                            "disclosure": row["disclosure"],
                            "policy": None,
                            "consent_id": row["id"],
                            "share_voice": row["share_voice"],
                            "occurred_at": row["revoked_at"],
                        },
                    )
                    inserted += 1
        user_after = user_rows[-1]["id"]

    op.add_column("audio_deletions", sa.Column("owner_id", sa.String(32), nullable=True))
    op.create_index("ix_audio_deletions_owner_id", "audio_deletions", ["owner_id"])
    # All server-generated keys have ``audio/{32-char owner}/{uuid}.enc``.
    # Recover ownership for durable crash tombstones created by the previous
    # release so an account purge cannot declare provider erasure complete
    # while one of those objects is still pending.
    op.execute(
        """UPDATE audio_deletions
              SET owner_id = substr(storage_key, 7, 32)
            WHERE owner_id IS NULL
              AND substr(storage_key, 1, 6) = 'audio/'
              AND substr(storage_key, 39, 1) = '/'"""
    )
    op.add_column("audio_deletions", sa.Column("created_at", sa.DateTime(timezone=True)))
    op.execute("UPDATE audio_deletions SET created_at = not_before WHERE created_at IS NULL")
    with op.batch_alter_table("audio_deletions") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    op.create_table(
        "audio_inventory_cursor",
        sa.Column("store_id", sa.String(64), primary_key=True),
        sa.Column("after_key", sa.String(256), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Historical rows used the v1 canonical payload (actor_role omitted).
    op.add_column(
        "access_log",
        sa.Column("record_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
    )
    op.add_column(
        "access_log",
        sa.Column("mac_key_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
    )
    with op.batch_alter_table("access_log") as batch:
        batch.alter_column("record_version", server_default=sa.text("2"))

    op.create_table(
        "audit_chain_state",
        sa.Column("user_id", sa.String(32), primary_key=True),
        sa.Column("head_seq", sa.BigInteger(), nullable=False),
        sa.Column("head_hash", sa.String(64), nullable=False),
        sa.Column("head_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_retained_seq", sa.BigInteger(), nullable=True),
        sa.Column("first_retained_hash", sa.String(64), nullable=True),
        sa.Column("state_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("mac_key_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        # NULL marks a migration snapshot that the application will seal
        # only after independently verifying the retained rows.
        sa.Column("state_mac", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    # PostgreSQL and SQLite both support window functions.  Backfill one
    # explicit state row for every historical owner so a later total/tail
    # deletion cannot masquerade as a brand-new chain.
    op.execute(
        """
        INSERT INTO audit_chain_state
          (user_id, head_seq, head_hash, head_at, first_retained_seq,
           first_retained_hash, state_version, mac_key_version, state_mac, updated_at)
        SELECT h.user_id, h.chain_seq, h.entry_hash, h.at,
               f.chain_seq, f.entry_hash, 1, 1, NULL, h.at
          FROM access_log h
          JOIN access_log f ON f.user_id = h.user_id
         WHERE h.chain_seq = (
                 SELECT MAX(h2.chain_seq) FROM access_log h2
                  WHERE h2.user_id = h.user_id
               )
           AND f.chain_seq = (
                 SELECT MIN(f2.chain_seq) FROM access_log f2
                  WHERE f2.user_id = h.user_id
               )
        """
    )
    op.create_table(
        "audit_sweep_cursor",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_user_id", sa.String(32), nullable=True),
        sa.Column("prune_last_user_id", sa.String(32), nullable=True),
        sa.Column("verification_cycle_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_owner_id", sa.String(32), nullable=True),
        sa.Column("verification_snapshot_head_seq", sa.BigInteger(), nullable=True),
        sa.Column("verification_snapshot_head_hash", sa.String(64), nullable=True),
        sa.Column("verification_next_seq", sa.BigInteger(), nullable=True),
        sa.Column("verification_previous_hash", sa.String(64), nullable=True),
        sa.Column(
            "verification_rows_checked",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("verification_mac_key_version", sa.Integer(), nullable=True),
        sa.Column("verification_checkpoint_mac", sa.String(64), nullable=True),
        sa.Column("prune_cycle_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table("audit_sweep_cursor")
    op.drop_table("audit_chain_state")
    op.drop_column("access_log", "mac_key_version")
    op.drop_column("access_log", "record_version")
    op.drop_table("audio_inventory_cursor")
    op.drop_column("audio_deletions", "created_at")
    op.drop_index("ix_audio_deletions_owner_id", table_name="audio_deletions")
    op.drop_column("audio_deletions", "owner_id")
    op.drop_index("ix_consent_events_user_at", table_name="consent_events")
    op.drop_table("consent_events")
    op.drop_index(
        "ix_account_deletion_tombstones_expiry",
        table_name="account_deletion_tombstones",
    )
    op.drop_table("account_deletion_tombstones")
    op.drop_index("ix_account_deletion_jobs_requested", table_name="account_deletion_jobs")
    op.drop_index("ix_account_deletion_jobs_phase", table_name="account_deletion_jobs")
    op.drop_index("ix_account_deletion_jobs_updated", table_name="account_deletion_jobs")
    op.drop_table("account_deletion_jobs")
    op.drop_index("ix_note_revisions_therapist_id", table_name="therapist_note_revisions")
    op.drop_index("ix_notes_user_id", table_name="therapist_notes")
    op.drop_index("ix_pairing_codes_therapist_id", table_name="pairing_codes")
    op.drop_column("users", "age_attested_at")
    op.drop_column("users", "age_attestation_version")
    op.drop_column("users", "patients_revision")
    op.drop_column("users", "consents_revision")
