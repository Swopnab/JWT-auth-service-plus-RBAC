-- Legacy 32-bit hashes cannot be upgraded without the original token.
-- Invalidate them; existing clients must sign in/request fresh reset links.
DELETE FROM refresh_tokens WHERE length(token_hash) != 64;
DELETE FROM password_reset_tokens WHERE length(token_hash) != 64;
DELETE FROM email_verification_tokens WHERE length(token_hash) != 64;
DELETE FROM sessions WHERE NOT EXISTS (
    SELECT 1 FROM refresh_tokens WHERE session_id = sessions.id AND revoked_at IS NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expiry ON rate_limits(expires_at);
