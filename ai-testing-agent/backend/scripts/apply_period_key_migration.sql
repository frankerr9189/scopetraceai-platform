-- ============================================================================
-- Migration: Add period_key to tenant_usage table
-- Revision: l7m8n9o0p1q2
-- Date: 2026-01-20
-- 
-- This script adds a deterministic period_key column to tenant_usage for
-- consistent lookups and eliminates timestamp precision mismatches.
-- 
-- Run this script directly in Supabase SQL Editor.
-- ============================================================================

-- Step 1: Add period_key column (nullable initially for backfill)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'tenant_usage' AND column_name = 'period_key'
    ) THEN
        ALTER TABLE tenant_usage ADD COLUMN period_key TEXT;
        RAISE NOTICE 'Added period_key column';
    ELSE
        RAISE NOTICE 'period_key column already exists';
    END IF;
END $$;

-- Step 2: Backfill period_key for existing rows
-- Format: "YYYY-MM" for calendar months, or "YYYY-MM-DD_YYYY-MM-DD" for Stripe periods
UPDATE tenant_usage
SET period_key = CASE
    -- If period is calendar month (1st to last day of month)
    -- Check if period_start is the 1st of the month
    -- and period_end is the last day of the same month
    WHEN EXTRACT(DAY FROM period_start) = 1 
         AND period_end = (DATE_TRUNC('MONTH', period_start) + INTERVAL '1 MONTH - 1 day')::date
    THEN TO_CHAR(period_start, 'YYYY-MM')
    -- Otherwise use full period range (Stripe periods or other)
    ELSE TO_CHAR(period_start, 'YYYY-MM-DD') || '_' || TO_CHAR(period_end, 'YYYY-MM-DD')
END
WHERE period_key IS NULL;

-- Step 3: Make period_key NOT NULL
DO $$
BEGIN
    -- Check if there are any NULL values
    IF EXISTS (SELECT 1 FROM tenant_usage WHERE period_key IS NULL) THEN
        RAISE EXCEPTION 'Cannot make period_key NOT NULL: % rows still have NULL period_key', 
            (SELECT COUNT(*) FROM tenant_usage WHERE period_key IS NULL);
    END IF;
    
    -- Set NOT NULL constraint
    ALTER TABLE tenant_usage ALTER COLUMN period_key SET NOT NULL;
    RAISE NOTICE 'Set period_key to NOT NULL';
END $$;

-- Step 4: Drop old unique constraint if it exists
DO $$
BEGIN
    -- Try to drop the old constraint (might have different names)
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE table_name = 'tenant_usage' 
        AND constraint_type = 'UNIQUE'
        AND constraint_name LIKE '%period_start%period_end%'
    ) THEN
        -- Find and drop the constraint
        EXECUTE (
            SELECT 'ALTER TABLE tenant_usage DROP CONSTRAINT IF EXISTS ' || constraint_name
            FROM information_schema.table_constraints 
            WHERE table_name = 'tenant_usage' 
            AND constraint_type = 'UNIQUE'
            AND constraint_name LIKE '%period_start%period_end%'
            LIMIT 1
        );
        RAISE NOTICE 'Dropped old unique constraint';
    ELSE
        RAISE NOTICE 'Old unique constraint not found (may have been dropped already)';
    END IF;
END $$;

-- Step 5: Add new unique constraint on (tenant_id, period_key)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE table_name = 'tenant_usage' 
        AND constraint_name = 'uq_tenant_usage_tenant_id_period_key'
    ) THEN
        ALTER TABLE tenant_usage 
        ADD CONSTRAINT uq_tenant_usage_tenant_id_period_key 
        UNIQUE (tenant_id, period_key);
        RAISE NOTICE 'Added unique constraint on (tenant_id, period_key)';
    ELSE
        RAISE NOTICE 'Unique constraint uq_tenant_usage_tenant_id_period_key already exists';
    END IF;
END $$;

-- Step 6: Add index for faster lookups
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE tablename = 'tenant_usage' 
        AND indexname = 'idx_tenant_usage_tenant_id_period_key'
    ) THEN
        CREATE INDEX idx_tenant_usage_tenant_id_period_key 
        ON tenant_usage (tenant_id, period_key);
        RAISE NOTICE 'Added index idx_tenant_usage_tenant_id_period_key';
    ELSE
        RAISE NOTICE 'Index idx_tenant_usage_tenant_id_period_key already exists';
    END IF;
END $$;

-- Step 7: Verify migration
DO $$
DECLARE
    row_count INTEGER;
    null_count INTEGER;
    constraint_exists BOOLEAN;
    index_exists BOOLEAN;
BEGIN
    -- Check column exists and is NOT NULL
    SELECT COUNT(*) INTO row_count FROM tenant_usage;
    SELECT COUNT(*) INTO null_count FROM tenant_usage WHERE period_key IS NULL;
    
    -- Check constraint exists
    SELECT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE table_name = 'tenant_usage' 
        AND constraint_name = 'uq_tenant_usage_tenant_id_period_key'
    ) INTO constraint_exists;
    
    -- Check index exists
    SELECT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE tablename = 'tenant_usage' 
        AND indexname = 'idx_tenant_usage_tenant_id_period_key'
    ) INTO index_exists;
    
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Migration Verification:';
    RAISE NOTICE '  Total rows: %', row_count;
    RAISE NOTICE '  Rows with NULL period_key: %', null_count;
    RAISE NOTICE '  Unique constraint exists: %', constraint_exists;
    RAISE NOTICE '  Index exists: %', index_exists;
    RAISE NOTICE '========================================';
    
    IF null_count > 0 THEN
        RAISE WARNING 'WARNING: % rows still have NULL period_key', null_count;
    END IF;
    
    IF constraint_exists AND index_exists AND null_count = 0 THEN
        RAISE NOTICE '✅ Migration completed successfully!';
    ELSE
        RAISE WARNING '⚠️  Migration may be incomplete. Please review the output above.';
    END IF;
END $$;
