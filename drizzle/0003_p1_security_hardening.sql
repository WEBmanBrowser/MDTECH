-- P1 Security Hardening
-- 1) rate_limits: persistent server-side rate limiting (atomic upsert)
-- 2) password_reset_tokens: hashed single-use reset tokens (60 min TTL)
-- 3) users.token_version: bump to invalidate all previously issued JWTs

CREATE TABLE "rate_limits" (
	"id" serial PRIMARY KEY NOT NULL,
	"bucket" varchar(255) NOT NULL,
	"window_start" timestamp NOT NULL,
	"count" integer DEFAULT 0 NOT NULL
);
CREATE UNIQUE INDEX "rate_limits_bucket_window_idx" ON "rate_limits" ("bucket","window_start");

CREATE TABLE "password_reset_tokens" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
CREATE UNIQUE INDEX "password_reset_tokens_token_hash_unique" ON "password_reset_tokens" ("token_hash");
CREATE INDEX "prt_user_idx" ON "password_reset_tokens" ("user_id");
ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;

ALTER TABLE "users" ADD COLUMN "token_version" integer DEFAULT 0 NOT NULL;
