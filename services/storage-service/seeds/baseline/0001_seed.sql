INSERT INTO storage_buckets (bucket_name, endpoint, region, is_default)
VALUES ('wildon-dev', 'https://s3.wasabisys.com', 'us-east-1', TRUE)
ON CONFLICT (bucket_name)
DO UPDATE
SET endpoint = EXCLUDED.endpoint,
    region = EXCLUDED.region,
    is_default = EXCLUDED.is_default;
