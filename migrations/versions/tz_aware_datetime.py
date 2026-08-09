"""timezone-aware datetime columns

Revision ID: tz_aware_datetime
Revises: 398b87fbd29c
Create Date: 2026-07-27

"""
from alembic import op
import sqlalchemy as sa

revision = 'tz_aware_datetime'
down_revision = '398b87fbd29c'
branch_labels = None
depends_on = None


def upgrade():
    # On PostgreSQL, ALTER COLUMN TYPE works.
    # On SQLite, ALTER COLUMN is not supported — skip silently.
    dialect = op.get_bind().dialect.name
    if dialect == 'postgresql':
        op.alter_column('requests', 'timestamp',
                         type_=sa.DateTime(timezone=True),
                         existing_nullable=True)
        op.alter_column('incidents', 'created_at',
                         type_=sa.DateTime(timezone=True),
                         existing_nullable=True)
        op.alter_column('alerted_ips', 'first_alerted_at',
                         type_=sa.DateTime(timezone=True),
                         existing_nullable=True)


def downgrade():
    dialect = op.get_bind().dialect.name
    if dialect == 'postgresql':
        op.alter_column('requests', 'timestamp',
                         type_=sa.DateTime(),
                         existing_nullable=True)
        op.alter_column('incidents', 'created_at',
                         type_=sa.DateTime(),
                         existing_nullable=True)
        op.alter_column('alerted_ips', 'first_alerted_at',
                         type_=sa.DateTime(),
                         existing_nullable=True)
