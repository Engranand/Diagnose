-- Creates the test database alongside the main database.
-- Mounted into postgres container at /docker-entrypoint-initdb.d/
-- and executed automatically on first initialisation.
CREATE DATABASE diagnose_test;
GRANT ALL PRIVILEGES ON DATABASE diagnose_test TO diagnose;
