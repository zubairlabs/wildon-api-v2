INSERT INTO export_kinds (export_kind, enabled)
VALUES
  ('profile', TRUE),
  ('trips', TRUE),
  ('devices', TRUE)
ON CONFLICT (export_kind)
DO UPDATE
SET enabled = EXCLUDED.enabled;
