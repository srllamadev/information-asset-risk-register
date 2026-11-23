"""Add institutional asset details and directional dependencies."""
from alembic import op
import sqlalchemy as sa

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

fields = [('asset_type', sa.String(100)), ('category', sa.String(150)), ('subcategory', sa.String(150)), ('process', sa.String(200)), ('owner', sa.String(200)), ('custodian', sa.String(200)), ('responsible', sa.String(200)), ('location', sa.String(200)), ('classification', sa.String(100)), ('review_date', sa.Date()), ('observations', sa.Text()), ('updated_at', sa.DateTime(timezone=True))]

def upgrade():
    for name, kind in fields:
        op.add_column('assets', sa.Column(name, kind, nullable=True))
    op.execute('UPDATE assets SET updated_at = created_at WHERE updated_at IS NULL')
    op.create_table('asset_dependencies', sa.Column('asset_id', sa.Integer, sa.ForeignKey('assets.id', ondelete='RESTRICT'), primary_key=True), sa.Column('depends_on_id', sa.Integer, sa.ForeignKey('assets.id', ondelete='RESTRICT'), primary_key=True), sa.CheckConstraint('asset_id != depends_on_id', name='ck_asset_dependency_not_self'))

def downgrade():
    op.drop_table('asset_dependencies')
    with op.batch_alter_table('assets') as batch:
        for name, _ in reversed(fields):
            batch.drop_column(name)
