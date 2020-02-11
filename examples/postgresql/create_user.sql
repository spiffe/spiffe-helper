-- Create test database
CREATE DATABASE testdb;

-- Create client user
CREATE USER "postgres-user" WITH ENCRYPTED PASSWORD '1234';

-- Grant privileges to postgres-user
GRANT ALL PRIVILEGES ON DATABASE testdb TO "postgres-user";
