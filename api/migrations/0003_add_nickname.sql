-- Migration: 0003_add_nickname.sql
-- Description: Add nickname column to users table for user personalization

ALTER TABLE users ADD COLUMN nickname TEXT;
