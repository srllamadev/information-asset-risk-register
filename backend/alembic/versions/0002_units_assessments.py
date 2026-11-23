"""Organizational units and historical CIA assessments."""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("organizational_units", sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(200), nullable=False))
    op.create_index("ix_organizational_units_name", "organizational_units", ["name"], unique=True)
    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("unit_id", sa.Integer, nullable=True))
        batch.create_foreign_key("fk_assets_unit", "organizational_units", ["unit_id"], ["id"], ondelete="RESTRICT")
        batch.create_index("ix_assets_unit_id", ["unit_id"])
    op.create_table("asset_assessments", sa.Column("id", sa.Integer, primary_key=True), sa.Column("asset_id", sa.Integer, sa.ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False), sa.Column("confidentiality", sa.Integer, nullable=False), sa.Column("integrity", sa.Integer, nullable=False), sa.Column("availability", sa.Integer, nullable=False), sa.Column("confidentiality_reason", sa.Text, nullable=False), sa.Column("integrity_reason", sa.Text, nullable=False), sa.Column("availability_reason", sa.Text, nullable=False), sa.Column("assessor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False), sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False), sa.CheckConstraint("confidentiality BETWEEN 1 AND 5", name="ck_asset_confidentiality"), sa.CheckConstraint("integrity BETWEEN 1 AND 5", name="ck_asset_integrity"), sa.CheckConstraint("availability BETWEEN 1 AND 5", name="ck_asset_availability"))
    op.create_index("ix_asset_assessments_asset_id", "asset_assessments", ["asset_id"])

def downgrade():
    op.drop_index("ix_asset_assessments_asset_id", table_name="asset_assessments")
    op.drop_table("asset_assessments")
    with op.batch_alter_table("assets") as batch:
        batch.drop_index("ix_assets_unit_id")
        batch.drop_constraint("fk_assets_unit", type_="foreignkey")
        batch.drop_column("unit_id")
    op.drop_index("ix_organizational_units_name", table_name="organizational_units")
    op.drop_table("organizational_units")
