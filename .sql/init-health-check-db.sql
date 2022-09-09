CREATE TABLE IF NOT EXISTS hosts (
  ip inet Primary Key,
  ipv6 boolean NOT NULL
);
