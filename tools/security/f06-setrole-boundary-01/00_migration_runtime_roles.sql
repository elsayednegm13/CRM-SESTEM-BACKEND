-- Sandbox-only precondition for migrations 028-030. These roles are not actors.
-- Product migrations verify configured LOGIN principals but do not create them.
CREATE ROLE daleel_f06b01_provider LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
CREATE ROLE daleel_f06b01_provider_control LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
