CREATE TABLE IF NOT EXISTS hosts (
  ip inet Primary Key,
  port smallint,
  ipv6 boolean NOT NULL
);
