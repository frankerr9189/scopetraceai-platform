"""map_subscription_status_to_new_tiers

Revision ID: h3i4j5k6l7m8
Revises: g2h3i4j5k6l7
Create Date: 2026-01-22 16:00:00.000000

Map old subscription_status values to new tier names:
- "free" -> "trial"
- "Trial" -> "trial"
- "paid" -> "individual" (assuming paid represented user tier)
- "Active" -> "individual" (assuming Active represented paid tier)
- "Paywalled" -> "paywalled" (keep as-is, just normalize case)

Do NOT change counters during mapping.
"""
from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision = 'h3i4j5k6l7m8'
down_revision = 'g2h3i4j5k6l7'  # remove_subscription_default_support_unselected
branch_labels = None
depends_on = None


def upgrade():
    """
    Normalize subscription_status to lowercase and map old values to new tier names.
    All values must be lowercase: "unselected", "trial", "individual", "team", "paywalled", "canceled"
    """
    conn = op.get_bind()
    
    # Map old values to new lowercase values
    # "free" -> "trial"
    free_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenants WHERE subscription_status = 'free'
    """)).scalar()
    if free_count > 0:
        conn.execute(text("""
            UPDATE tenants
            SET subscription_status = 'trial'
            WHERE subscription_status = 'free'
        """))
        print(f"Mapped {free_count} tenant(s) from 'free' to 'trial'")
    
    # "Trial" -> "trial" (normalize case)
    trial_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenants WHERE subscription_status = 'Trial'
    """)).scalar()
    if trial_count > 0:
        conn.execute(text("""
            UPDATE tenants
            SET subscription_status = 'trial'
            WHERE subscription_status = 'Trial'
        """))
        print(f"Mapped {trial_count} tenant(s) from 'Trial' to 'trial'")
    
    # "paid" -> "individual" (assuming paid represented user tier)
    paid_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenants WHERE subscription_status = 'paid'
    """)).scalar()
    if paid_count > 0:
        conn.execute(text("""
            UPDATE tenants
            SET subscription_status = 'individual'
            WHERE subscription_status = 'paid'
        """))
        print(f"Mapped {paid_count} tenant(s) from 'paid' to 'individual'")
    
    # "Active" -> "individual" (assuming Active represented paid tier)
    active_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenants WHERE subscription_status = 'Active'
    """)).scalar()
    if active_count > 0:
        conn.execute(text("""
            UPDATE tenants
            SET subscription_status = 'individual'
            WHERE subscription_status = 'Active'
        """))
        print(f"Mapped {active_count} tenant(s) from 'Active' to 'individual'")
    
    # "Paywalled" -> "paywalled" (normalize case)
    paywalled_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenants WHERE subscription_status = 'Paywalled'
    """)).scalar()
    if paywalled_count > 0:
        conn.execute(text("""
            UPDATE tenants
            SET subscription_status = 'paywalled'
            WHERE subscription_status = 'Paywalled'
        """))
        print(f"Mapped {paywalled_count} tenant(s) from 'Paywalled' to 'paywalled'")
    
    # Handle any other case variations (case-insensitive normalization)
    # This catches any remaining uppercase/mixed case variations
    case_variations = conn.execute(text("""
        SELECT DISTINCT subscription_status
        FROM tenants
        WHERE LOWER(subscription_status) IN ('trial', 'individual', 'team', 'paywalled', 'canceled', 'unselected')
          AND subscription_status != LOWER(subscription_status)
    """)).fetchall()
    
    if case_variations:
        for (status,) in case_variations:
            normalized = status.lower()
            count = conn.execute(text("""
                SELECT COUNT(*) FROM tenants WHERE subscription_status = :status
            """), {"status": status}).scalar()
            conn.execute(text("""
                UPDATE tenants
                SET subscription_status = :normalized
                WHERE subscription_status = :status
            """), {"normalized": normalized, "status": status})
            print(f"Mapped {count} tenant(s) from '{status}' to '{normalized}' (case normalization)")
    
    # Log any unmapped values for manual review
    unmapped = conn.execute(text("""
        SELECT DISTINCT subscription_status
        FROM tenants
        WHERE LOWER(subscription_status) NOT IN ('unselected', 'trial', 'individual', 'team', 'paywalled', 'canceled')
    """)).fetchall()
    
    if unmapped:
        print(f"WARNING: Found unmapped subscription_status values: {[row[0] for row in unmapped]}")
        print("These tenants should be reviewed manually.")
    
    conn.commit()
    print("Subscription status normalization and mapping complete.")


def downgrade():
    """
    Reverse mapping (not recommended - this would break new tier system).
    """
    conn = op.get_bind()
    
    # Reverse mappings (approximate)
    conn.execute(text("""
        UPDATE tenants
        SET subscription_status = 'Trial'
        WHERE subscription_status = 'trial'
    """))
    
    conn.execute(text("""
        UPDATE tenants
        SET subscription_status = 'Active'
        WHERE subscription_status IN ('individual', 'team')
    """))
    
    conn.execute(text("""
        UPDATE tenants
        SET subscription_status = 'Paywalled'
        WHERE subscription_status = 'paywalled'
    """))
    
    print("Reversed subscription status mapping (WARNING: This breaks new tier system)")
