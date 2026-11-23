"""Manage asset categories and preserve existing category names."""
from alembic import op
import sqlalchemy as sa
revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('asset_categories', sa.Column('id', sa.Integer, primary_key=True), sa.Column('name', sa.String(150), nullable=False), sa.Column('active', sa.Boolean, nullable=False))
    op.create_index('ix_asset_categories_name', 'asset_categories', ['name'], unique=True)
    op.execute("INSERT INTO asset_categories(name, active) SELECT DISTINCT category, 1 FROM assets WHERE category IS NOT NULL AND trim(category) != ''")

def downgrade():
    op.drop_index('ix_asset_categories_name', table_name='asset_categories')
    op.drop_table('asset_categories')
