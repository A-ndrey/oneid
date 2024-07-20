-- +goose Up
-- +goose StatementBegin
CREATE TABLE users
(
    id char(20) not null unique,
    email varchar(255) not null,
    password varchar(255) not null,
    email_confirmed int(1) not null default false,
    first_name varchar(255) not null default '',
    last_name varchar(255) not null default '',
    role varchar(10) not null default 'user',
    mfa varchar(255) not null default '',
    mfa_shared_secret varchar(255) not null default ''
);

CREATE TABLE sessions
(
    user_id      char(20) not null,
    user_agent   varchar(255) not null,
    hashed_token varchar(255) not null,
    exp_date     timestamp not null
);

CREATE TABLE apps
(
    id char(20) not null unique,
    name varchar(255) not null,
    hashed_secret varchar(255) not null
)
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
DROP TABLE sessions;
DROP TABLE apps;
-- +goose StatementEnd
