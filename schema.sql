CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    paypal_email VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'worker'
        CHECK (role IN ('worker', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS screenings (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    answers JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    review_notes TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    task_type VARCHAR(40) NOT NULL,
    media_url TEXT,
    media_type VARCHAR(20),
    reward_usd NUMERIC(10,2) NOT NULL DEFAULT 0
        CHECK (reward_usd >= 0),
    published BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS submissions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    task_id BIGINT NOT NULL REFERENCES tasks(id),
    response JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    review_notes TEXT,
    UNIQUE (user_id, task_id)
);

CREATE TABLE IF NOT EXISTS payouts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    amount_usd NUMERIC(10,2) NOT NULL CHECK (amount_usd > 0),
    paypal_email VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'paid', 'rejected')),
    transaction_id TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paid_at TIMESTAMPTZ,
    admin_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_screenings_status
    ON screenings(status);

CREATE INDEX IF NOT EXISTS idx_tasks_published
    ON tasks(published);

CREATE INDEX IF NOT EXISTS idx_submissions_status
    ON submissions(status);

CREATE INDEX IF NOT EXISTS idx_payouts_status
    ON payouts(status);
