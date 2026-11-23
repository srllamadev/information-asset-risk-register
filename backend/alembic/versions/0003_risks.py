"""Risk scenarios and append-only assessments."""
from alembic import op
import sqlalchemy as sa
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

def upgrade():
    for table in ("threats", "vulnerabilities"):
        op.create_table(table, sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(200), nullable=False), sa.Column("description", sa.Text, nullable=False), sa.Column("category", sa.String(100), nullable=False), sa.Column("active", sa.Boolean, nullable=False))
        op.create_index(f"ix_{table}_name", table, ["name"], unique=True)
    op.create_table("risk_scenarios", sa.Column("id", sa.Integer, primary_key=True), sa.Column("asset_id", sa.Integer, sa.ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False), sa.Column("threat_id", sa.Integer, sa.ForeignKey("threats.id", ondelete="RESTRICT"), nullable=False), sa.Column("vulnerability_id", sa.Integer, sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False), sa.Column("event", sa.Text, nullable=False), sa.Column("causes", sa.Text, nullable=False), sa.Column("consequences", sa.Text, nullable=False), sa.Column("owner", sa.String(200), nullable=False), sa.Column("identified_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_risk_scenarios_asset_id", "risk_scenarios", ["asset_id"])
    fields = ("inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact")
    op.create_table("risk_assessments", sa.Column("id", sa.Integer, primary_key=True), sa.Column("risk_id", sa.Integer, sa.ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), nullable=False), *(sa.Column(field, sa.Integer, nullable=False) for field in fields), sa.Column("existing_controls", sa.Text, nullable=False), sa.Column("effectiveness", sa.Text, nullable=False), sa.Column("justification", sa.Text, nullable=False), sa.Column("methodology", sa.Text, nullable=False), sa.Column("assessor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False), sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False), *(sa.CheckConstraint(f"{field} BETWEEN 1 AND 5", name=f"ck_risk_{field}") for field in fields))
    op.create_index("ix_risk_assessments_risk_id", "risk_assessments", ["risk_id"])

def downgrade():
    op.drop_index("ix_risk_assessments_risk_id", table_name="risk_assessments")
    op.drop_table("risk_assessments")
    op.drop_index("ix_risk_scenarios_asset_id", table_name="risk_scenarios")
    op.drop_table("risk_scenarios")
    for table in ("vulnerabilities", "threats"):
        op.drop_index(f"ix_{table}_name", table_name=table)
        op.drop_table(table)
