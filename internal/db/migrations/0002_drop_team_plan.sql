ALTER TABLE teams DROP COLUMN IF EXISTS plan;
ALTER TABLE teams DROP COLUMN IF EXISTS subscription_status;
ALTER TABLE teams DROP COLUMN IF EXISTS subscription_period_end;
ALTER TABLE teams DROP COLUMN IF EXISTS cancel_at_period_end;
