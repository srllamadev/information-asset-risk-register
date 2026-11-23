"""Security controls, treatment plans and links."""
from alembic import op
import sqlalchemy as sa
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("security_controls", sa.Column("id", sa.Integer, primary_key=True), sa.Column("code", sa.String(80), nullable=False), sa.Column("name", sa.String(200), nullable=False), sa.Column("description", sa.Text, nullable=False), sa.Column("source", sa.String(200), nullable=False), sa.Column("reference", sa.String(200), nullable=False), sa.Column("control_type", sa.String(100), nullable=False), sa.Column("implementation_status", sa.String(100), nullable=False), sa.Column("owner", sa.String(200), nullable=False), sa.Column("evidence", sa.Text, nullable=False), sa.Column("review_date", sa.String(10)))
    op.create_index("ix_security_controls_code", "security_controls", ["code"], unique=True)
    op.create_table("risk_treatments", sa.Column("id", sa.Integer, primary_key=True), sa.Column("risk_id", sa.Integer, sa.ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), nullable=False), sa.Column("strategy", sa.String(20), nullable=False), sa.Column("description", sa.Text, nullable=False), sa.Column("owner", sa.String(200), nullable=False), sa.Column("start_date", sa.String(10), nullable=False), sa.Column("target_date", sa.String(10), nullable=False), sa.Column("priority", sa.String(20), nullable=False), sa.Column("status", sa.String(20), nullable=False), sa.Column("evidence", sa.Text, nullable=False), sa.Column("observations", sa.Text, nullable=False), sa.Column("acceptance_authority", sa.String(200), nullable=False), sa.Column("acceptance_justification", sa.Text, nullable=False), sa.Column("acceptance_date", sa.String(10)), sa.Column("acceptance_review_date", sa.String(10)))
    op.create_index("ix_risk_treatments_risk_id", "risk_treatments", ["risk_id"])
    op.create_table("risk_controls", sa.Column("risk_id", sa.Integer, sa.ForeignKey("risk_scenarios.id", ondelete="RESTRICT"), primary_key=True), sa.Column("control_id", sa.Integer, sa.ForeignKey("security_controls.id", ondelete="RESTRICT"), primary_key=True))
    op.create_table("treatment_controls", sa.Column("treatment_id", sa.Integer, sa.ForeignKey("risk_treatments.id", ondelete="RESTRICT"), primary_key=True), sa.Column("control_id", sa.Integer, sa.ForeignKey("security_controls.id", ondelete="RESTRICT"), primary_key=True))

def downgrade():
    op.drop_table("treatment_controls")
    op.drop_table("risk_controls")
    op.drop_index("ix_risk_treatments_risk_id", table_name="risk_treatments")
    op.drop_table("risk_treatments")
    op.drop_index("ix_security_controls_code", table_name="security_controls")
    op.drop_table("security_controls")
