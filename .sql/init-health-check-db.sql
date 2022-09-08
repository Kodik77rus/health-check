CREATE TABLE IF NOT EXISTS hosts (
  ip inet Primary Key,
  port serial NOT NULL,
  ipv6 boolean NOT NULL
);
