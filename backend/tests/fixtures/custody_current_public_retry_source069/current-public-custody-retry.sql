BEGIN TRANSACTION;
CREATE TABLE access_log (
	id VARCHAR(32) NOT NULL,
	actor_id VARCHAR(32) NOT NULL,
	actor_role VARCHAR(16) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	action VARCHAR(32) NOT NULL,
	at DATETIME NOT NULL,
	chain_seq BIGINT DEFAULT 1 NOT NULL,
	prev_hash VARCHAR(64),
	entry_hash VARCHAR(64),
	entry_mac VARCHAR(64),
	mac_key_version INTEGER DEFAULT 1 NOT NULL,
	record_version INTEGER DEFAULT 2 NOT NULL,
	PRIMARY KEY (id)
);
INSERT INTO "access_log" VALUES('738140cee0f54a4c8b910998c46b5967','e49b9a5ad8b347ae9b2df9b75499591f','therapist','e49b9a5ad8b347ae9b2df9b75499591f','account_created','2026-10-23 00:42:58.564911',1,NULL,'584ad431bae0c6acc90600876ca31552e8b6bde1cc6d8207fcef6645aa87e32f','9f5a9571cb6c3e41ff8d6a5103841f7295324795ad81eb415781172f96eb855f',1,2);
INSERT INTO "access_log" VALUES('0a2d5e9fb6294dec9c7577df8597fa1c','e49b9a5ad8b347ae9b2df9b75499591f','therapist','e49b9a5ad8b347ae9b2df9b75499591f','totp_setup','2026-10-23 00:42:58.746444',2,'584ad431bae0c6acc90600876ca31552e8b6bde1cc6d8207fcef6645aa87e32f','b1aec6b3df9e1ef0e1857280db52ed63fd8fe70f83526f2d26a86458fd919cd7','4fa0ae50982a36f8556b9454cd4cfdba84b84264d9a59075f343e79e4c14ab34',1,2);
INSERT INTO "access_log" VALUES('87044c0beb8e40a88c5e8bd4106305a2','e49b9a5ad8b347ae9b2df9b75499591f','therapist','e49b9a5ad8b347ae9b2df9b75499591f','totp_enable','2026-10-23 00:42:58.926831',3,'b1aec6b3df9e1ef0e1857280db52ed63fd8fe70f83526f2d26a86458fd919cd7','cb64af8b76661f146f06cea5df92654c33d0f7f813d8339066eaf1a4925c97b1','d3adb7f4a21dc31cf942af9fa9883b265ae007da2a0c1dd5c8d1c66f7a3e8299',1,2);
INSERT INTO "access_log" VALUES('20c3490dc4564e7bb48fef2b494fbad8','e49b9a5ad8b347ae9b2df9b75499591f','therapist','e49b9a5ad8b347ae9b2df9b75499591f','notes_custody_install','2026-10-23 00:42:59.106968',4,'cb64af8b76661f146f06cea5df92654c33d0f7f813d8339066eaf1a4925c97b1','8d2e10f0af652c13875859f2895cde9f94fdbd4337c8c97b070b13366a1e7502','27ac9181d91c5fda1ceeef29ea14d31351b94d2244b3f0cb6463c9a93d8097b4',1,2);
CREATE TABLE account_deletion_jobs (
	user_id VARCHAR(32) NOT NULL,
	role VARCHAR(16) NOT NULL,
	phase VARCHAR(32) DEFAULT 'note_revisions' NOT NULL,
	attempts INTEGER DEFAULT 0 NOT NULL,
	requested_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (user_id)
);
CREATE TABLE account_deletion_tombstones (
	user_id VARCHAR(32) NOT NULL,
	role VARCHAR(16) NOT NULL,
	token_epoch BIGINT NOT NULL,
	auth_secret_version INTEGER NOT NULL,
	deleted_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	record_version INTEGER DEFAULT 1 NOT NULL,
	record_mac VARCHAR(64) NOT NULL,
	PRIMARY KEY (user_id)
);
CREATE TABLE audio_attachments (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	client_entry_id VARCHAR(64) NOT NULL,
	backend VARCHAR(8) NOT NULL,
	storage_key VARCHAR(256) NOT NULL,
	storage_locator VARCHAR(2048),
	size_bytes INTEGER NOT NULL,
	mime_type VARCHAR(64) NOT NULL,
	duration_seconds INTEGER NOT NULL,
	content_version INTEGER DEFAULT 1 NOT NULL,
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_audio_user_client_entry UNIQUE (user_id, client_entry_id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE audio_deletions (
	id VARCHAR(32) NOT NULL,
	owner_id VARCHAR(32),
	backend VARCHAR(8) NOT NULL,
	storage_key VARCHAR(256) NOT NULL,
	storage_locator VARCHAR(2048),
	not_before DATETIME NOT NULL,
	attempts INTEGER DEFAULT 0 NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id)
);
CREATE TABLE audio_inventory_cursor (
	store_id VARCHAR(64) NOT NULL,
	after_key VARCHAR(256),
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (store_id)
);
CREATE TABLE audit_chain_state (
	user_id VARCHAR(32) NOT NULL,
	head_seq BIGINT NOT NULL,
	head_hash VARCHAR(64) NOT NULL,
	head_at DATETIME NOT NULL,
	first_retained_seq BIGINT,
	first_retained_hash VARCHAR(64),
	state_version INTEGER DEFAULT 1 NOT NULL,
	mac_key_version INTEGER DEFAULT 1 NOT NULL,
	state_mac VARCHAR(64),
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (user_id)
);
INSERT INTO "audit_chain_state" VALUES('e49b9a5ad8b347ae9b2df9b75499591f',4,'8d2e10f0af652c13875859f2895cde9f94fdbd4337c8c97b070b13366a1e7502','2026-10-23 00:42:59.106968',1,'584ad431bae0c6acc90600876ca31552e8b6bde1cc6d8207fcef6645aa87e32f',1,1,'1ad538de69ae9e773aae108bf2f8dbb6eacb761ea3f300e21c10909c5e0f46fe','2026-10-23 00:42:59.106968');
CREATE TABLE audit_sweep_cursor (
	id INTEGER NOT NULL,
	last_user_id VARCHAR(32),
	prune_last_user_id VARCHAR(32),
	verification_cycle_started_at DATETIME,
	verification_owner_id VARCHAR(32),
	verification_snapshot_head_seq BIGINT,
	verification_snapshot_head_hash VARCHAR(64),
	verification_next_seq BIGINT,
	verification_previous_hash VARCHAR(64),
	verification_rows_checked BIGINT DEFAULT 0 NOT NULL,
	verification_mac_key_version INTEGER,
	verification_checkpoint_mac VARCHAR(64),
	prune_cycle_started_at DATETIME,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (id)
);
INSERT INTO "audit_sweep_cursor" VALUES(1,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,1,'b962aa24c76745ce05d1b16dbed5e4f120bcdbb4376f0e6a16fccec62d1146bb',NULL,'2026-10-23 00:42:58.363382');
CREATE TABLE consent_events (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	kind VARCHAR(16) NOT NULL,
	action VARCHAR(16) NOT NULL,
	disclosure VARCHAR(64),
	policy VARCHAR(64),
	consent_id VARCHAR(32),
	share_voice BOOLEAN,
	event_version INTEGER DEFAULT 1 NOT NULL,
	occurred_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE consents (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	therapist_id VARCHAR(32) NOT NULL,
	status VARCHAR(16) DEFAULT 'active' NOT NULL,
	scope VARCHAR(16) DEFAULT 'full' NOT NULL,
	granted_at DATETIME NOT NULL,
	revoked_at DATETIME,
	ephemeral_pub VARCHAR(256),
	wrapped_key BLOB,
	summary_blob BLOB,
	summary_eph_pub VARCHAR(256),
	summary_updated_at DATETIME,
	disclosure VARCHAR(64),
	share_voice BOOLEAN DEFAULT false NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_consents_user_therapist UNIQUE (user_id, therapist_id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY(therapist_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE entries (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	client_entry_id VARCHAR(64) NOT NULL,
	blob BLOB NOT NULL,
	entry_date DATE NOT NULL,
	received_at DATETIME NOT NULL,
	content_version BIGINT DEFAULT 1 NOT NULL,
	aad_guard_version SMALLINT DEFAULT 0 NOT NULL,
	aad_guard_key_version INTEGER,
	aad_guard_mac VARCHAR(64),
	PRIMARY KEY (id),
	CONSTRAINT uq_user_client_entry UNIQUE (user_id, client_entry_id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE entry_guard_bootstrap (
	id INTEGER NOT NULL,
	completed_at DATETIME,
	PRIMARY KEY (id)
);
CREATE TABLE insights (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	kind VARCHAR(32) NOT NULL,
	for_date DATE,
	blob BLOB NOT NULL,
	state_seq BIGINT DEFAULT 0 NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_insights_user_kind_date UNIQUE (user_id, kind, for_date),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE measures (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	client_measure_id VARCHAR(64) NOT NULL,
	blob BLOB NOT NULL,
	measure_date DATE NOT NULL,
	received_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_user_client_measure UNIQUE (user_id, client_measure_id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE pairing_codes (
	id VARCHAR(32) NOT NULL,
	therapist_id VARCHAR(32) NOT NULL,
	code_hash VARCHAR(128) NOT NULL,
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	consumed_at DATETIME,
	PRIMARY KEY (id),
	CONSTRAINT uq_pairing_codes_code_hash UNIQUE (code_hash),
	FOREIGN KEY(therapist_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE rekey_journal (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	operation_id VARCHAR(36),
	request_digest VARCHAR(64),
	old_key_fingerprint VARCHAR(64),
	new_key_fingerprint VARCHAR(64),
	stage VARCHAR(16) NOT NULL,
	entry_cursor VARCHAR(32),
	measure_cursor VARCHAR(32),
	entries_done BIGINT DEFAULT 0 NOT NULL,
	insights_done BIGINT DEFAULT 0 NOT NULL,
	measures_done BIGINT DEFAULT 0 NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (id)
);
CREATE TABLE therapist_note_revisions (
	id VARCHAR(32) NOT NULL,
	note_id VARCHAR(32) NOT NULL,
	therapist_id VARCHAR(32) NOT NULL,
	blob BLOB NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(note_id) REFERENCES therapist_notes (id) ON DELETE CASCADE,
	FOREIGN KEY(therapist_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE therapist_notes (
	id VARCHAR(32) NOT NULL,
	therapist_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	client_note_id VARCHAR(64) NOT NULL,
	pattern_pid VARCHAR(200),
	blob BLOB NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	version BIGINT DEFAULT 1 NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_notes_therapist_client UNIQUE (therapist_id, client_note_id),
	FOREIGN KEY(therapist_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE token_revocation (
	jti VARCHAR(64) NOT NULL,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (jti)
);
CREATE TABLE totp_backup_codes (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	digest VARCHAR(64) NOT NULL,
	used_at DATETIME,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
INSERT INTO "totp_backup_codes" VALUES('81cd9971c1cc42509812485c31ea0b54','e49b9a5ad8b347ae9b2df9b75499591f','343527a95303392bb629edca5c317819b70b61dac49d813608fc5b3733c5cbc3',NULL,'2026-10-23 00:42:58.927326');
INSERT INTO "totp_backup_codes" VALUES('2604b08cb5614fa3937d4b7eda36162d','e49b9a5ad8b347ae9b2df9b75499591f','50d529ce590eafa5b8349c3a46ca7137b54f5cecf495de95cf37f68a86292cf2',NULL,'2026-10-23 00:42:58.927331');
INSERT INTO "totp_backup_codes" VALUES('828e4db553294b2b8d68ecf212e3f383','e49b9a5ad8b347ae9b2df9b75499591f','2a68aa16954909bd2613ae49959db21f7ba3eb52959d3e08cd2f3d7eb4d570b8',NULL,'2026-10-23 00:42:58.927334');
INSERT INTO "totp_backup_codes" VALUES('fd89756319e440708bb02bbc3a35a687','e49b9a5ad8b347ae9b2df9b75499591f','b16b70d4565d9e907ebd16cff65497b816592c619bc3ed3c64e2540f8f687978',NULL,'2026-10-23 00:42:58.927336');
INSERT INTO "totp_backup_codes" VALUES('3ff1ebdd04e64e158eb6740cee277391','e49b9a5ad8b347ae9b2df9b75499591f','ff224b9d6db9f2a232c0b5d70a9f9a1bda019831949773517b127a0644fb0c72',NULL,'2026-10-23 00:42:58.927338');
INSERT INTO "totp_backup_codes" VALUES('887b770196534229b1bee82f1c3bdee9','e49b9a5ad8b347ae9b2df9b75499591f','0eccff10a62db67cf25b838e6b9312c26c210204ffd7026289ca45e84331f44d',NULL,'2026-10-23 00:42:58.927341');
INSERT INTO "totp_backup_codes" VALUES('46e1086f6d2b42bdb0a112c57bfe32c2','e49b9a5ad8b347ae9b2df9b75499591f','209b083d48f98b01edc0c37f734120bb1cacb5ad5b83a67f075436fc87d3c75b',NULL,'2026-10-23 00:42:58.927343');
INSERT INTO "totp_backup_codes" VALUES('5f4a06eb56434eda83e679703a41546a','e49b9a5ad8b347ae9b2df9b75499591f','4ad2641e1196e8cc22f1e67571788fd927ae0ead22beef6e92226a6e5570aed8',NULL,'2026-10-23 00:42:58.927345');
CREATE TABLE users (
	id VARCHAR(32) NOT NULL,
	username VARCHAR(64) NOT NULL,
	salt VARCHAR(128) NOT NULL,
	verifier BLOB NOT NULL,
	scrypt_salt BLOB NOT NULL,
	created_at DATETIME NOT NULL,
	is_active BOOLEAN NOT NULL,
	age_attestation_version VARCHAR(32),
	age_attested_at DATETIME,
	role VARCHAR(16) DEFAULT 'user' NOT NULL,
	display_name VARCHAR(120),
	wrap_pub_key VARCHAR(256),
	wrap_key_blob BLOB,
	notes_keyring_blob BLOB,
	custody_version BIGINT DEFAULT 0 NOT NULL,
	custody_operation_id VARCHAR(36),
	custody_operation_digest VARCHAR(64),
	custody_operation_epoch INTEGER,
	rekey_operation_id VARCHAR(36),
	rekey_operation_digest VARCHAR(64),
	rekey_operation_epoch INTEGER,
	rekey_operation_result TEXT,
	token_epoch INTEGER NOT NULL,
	entries_revision BIGINT DEFAULT 0 NOT NULL,
	notes_revision BIGINT DEFAULT 0 NOT NULL,
	measures_revision BIGINT DEFAULT 0 NOT NULL,
	consents_revision BIGINT DEFAULT 0 NOT NULL,
	patients_revision BIGINT DEFAULT 0 NOT NULL,
	llm_consent BOOLEAN NOT NULL,
	llm_consent_at DATETIME,
	llm_consent_disclosure VARCHAR(64),
	llm_consent_policy VARCHAR(64),
	voice_consent BOOLEAN DEFAULT false NOT NULL,
	voice_consent_at DATETIME,
	voice_consent_disclosure VARCHAR(64),
	voice_consent_policy VARCHAR(64),
	totp_secret VARCHAR(256),
	totp_enabled BOOLEAN,
	totp_last_counter INTEGER,
	key_scheme VARCHAR(8) DEFAULT 'v1' NOT NULL,
	wrapped_data_key BLOB,
	recovery_salt BLOB,
	recovery_verifier BLOB,
	recovery_wrapped_data_key BLOB,
	recovery_set_at DATETIME,
	recovery_scheme SMALLINT,
	entry_count INTEGER DEFAULT 0 NOT NULL,
	entry_blob_bytes BIGINT DEFAULT 0 NOT NULL,
	measure_count INTEGER DEFAULT 0 NOT NULL,
	kdf_params VARCHAR(256),
	PRIMARY KEY (id)
);
INSERT INTO "users" VALUES('e49b9a5ad8b347ae9b2df9b75499591f','native-persisted-custody-retry','Ne3VqNXehSbVAPHWwipsGQ==',X'C6085556AFF312F90DAD36F455D5771F2690A7E21B0AA4D36E4C2E7BEBAB07D29A536A1ED9311A9828E3AFE8A94EFC299BCFA1158E818774BC53EB4C35FA040F',X'4DD496B088EE62BA859CB5925EF1F80C','2026-10-23 00:42:58.564463',1,'minimum_age_confirmed_v1','2026-10-23 00:42:58.563694','therapist','Dr. Native-Persisted-Custody-Retry','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAxFuW6Jz2VB09AvfdiRgh4JSdRu2efdqD8aM2LpBmiu2qwpNL1MuylCnckgupP9RCI2ssS6DWXnkrxbxvSRJZg==',X'B2D44EBECD2FB4A228C24FD329644B434C7B8A6B39AB969F764C5D5ED5F5D9952354B4EF31BDDC6E7947BE3135F31F4ED7F8CDD98BAE5635D9F9A2E7DFA115EE88CD848E521EDE9E37F5FB2E5DD68F7B6BF64BD8FC49C2959E9814D86630F618941F1DC821DB41F3BD9C8DDE0DA0193B84B93771956644CA351717C68B0D54942E1E2204798DAC990AF683F383D1553C91CA7FB2FA265403876043CC676C336FFDF7E609D504',X'DECD3D30E8CFF3E1D678F022C99C65926B320D6B553A50C341C8E81E',1,'91af972a-6d77-4de5-afb2-d680194da3c1','88a1ede44a3665e2045b5c1351d01906ae15f42f6ac500f4565dbe74cf06bde0',1,NULL,NULL,NULL,NULL,1,0,1,0,0,0,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'v1:5/iZlkJ1YdGRl76KiQDFBQUZn/Imp88QHgd8ogU/HapR4Z+UWNJXLvrnNBwpOlf6',1,59757205,'v1',NULL,NULL,NULL,NULL,NULL,NULL,0,0,0,NULL);
CREATE UNIQUE INDEX ix_users_username ON users (username);
CREATE INDEX ix_account_deletion_tombstones_expiry ON account_deletion_tombstones (expires_at);
CREATE INDEX ix_account_deletion_jobs_phase ON account_deletion_jobs (phase);
CREATE INDEX ix_account_deletion_jobs_requested ON account_deletion_jobs (requested_at);
CREATE INDEX ix_account_deletion_jobs_updated ON account_deletion_jobs (updated_at, user_id);
CREATE INDEX ix_audio_deletions_not_before ON audio_deletions (not_before);
CREATE INDEX ix_audio_deletions_owner_id ON audio_deletions (owner_id);
CREATE INDEX ix_access_log_actor ON access_log (actor_id, at);
CREATE INDEX ix_access_log_user ON access_log (user_id, at);
CREATE INDEX ix_access_log_at ON access_log (at);
CREATE UNIQUE INDEX uq_access_log_user_chain_seq ON access_log (user_id, chain_seq);
CREATE INDEX ix_token_revocation_expiry ON token_revocation (expires_at);
CREATE INDEX ix_rekey_journal_user ON rekey_journal (user_id);
CREATE INDEX ix_totp_backup_codes_user_id ON totp_backup_codes (user_id);
CREATE INDEX ix_entries_user_received_id ON entries (user_id, received_at, id);
CREATE INDEX ix_entries_user_date ON entries (user_id, entry_date);
CREATE INDEX ix_insights_user_kind_date ON insights (user_id, kind, for_date);
CREATE UNIQUE INDEX uq_insights_user_kind_undated ON insights (user_id, kind) WHERE for_date IS NULL;
CREATE INDEX ix_consents_therapist_status ON consents (therapist_id, status);
CREATE INDEX ix_consent_events_user_at ON consent_events (user_id, occurred_at);
CREATE INDEX ix_measures_user_date ON measures (user_id, measure_date);
CREATE INDEX ix_pairing_codes_therapist_id ON pairing_codes (therapist_id);
CREATE INDEX ix_pairing_codes_expires_at ON pairing_codes (expires_at);
CREATE INDEX ix_notes_therapist_patient_created ON therapist_notes (therapist_id, user_id, created_at, id);
CREATE INDEX ix_notes_user_id ON therapist_notes (user_id);
CREATE INDEX ix_audio_user_expires ON audio_attachments (user_id, expires_at);
CREATE INDEX ix_note_revisions_therapist_id ON therapist_note_revisions (therapist_id);
CREATE INDEX ix_note_revisions_note_created ON therapist_note_revisions (note_id, created_at);
COMMIT;
