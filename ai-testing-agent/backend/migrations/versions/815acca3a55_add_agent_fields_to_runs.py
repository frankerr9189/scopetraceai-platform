"""add_agent_fields_to_runs

Revision ID: 815acca3a55
Revises: a1b2c3d4e5f6
Create Date: 2026-01-17 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '815acca3a55'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to runs table
    op.add_column('runs', sa.Column('agent', sa.String(), nullable=False, server_default='testing-agent'))
    op.add_column('runs', sa.Column('run_kind', sa.String(), nullable=False, server_default='test_plan'))
    op.add_column('runs', sa.Column('artifact_type', sa.String(), nullable=True))
    op.add_column('runs', sa.Column('artifact_id', sa.String(), nullable=True))
    op.add_column('runs', sa.Column('summary', sa.Text(), nullable=True))
    op.add_column('runs', sa.Column('input_ticket_count', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('runs', sa.Column('output_item_count', sa.Integer(), nullable=True, server_default='0'))


def downgrade():
    # Remove columns
    op.drop_column('runs', 'output_item_count')
    op.drop_column('runs', 'input_ticket_count')
    op.drop_column('runs', 'summary')
    op.drop_column('runs', 'artifact_id')
    op.drop_column('runs', 'artifact_type')
    op.drop_column('runs', 'run_kind')
    op.drop_column('runs', 'agent')
