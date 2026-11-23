"""Initial users, assets and audit log."""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("users", sa.Column("id", sa.Integer, primary_key=True), sa.Column("username", sa.String(100), nullable=False), sa.Column("password_hash", sa.String(255), nullable=False), sa.Column("role", sa.String(30), nullable=False), sa.Column("active", sa.Boolean, nullable=False), sa.Column("last_login", sa.DateTime(timezone=True)))
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_table("assets", sa.Column("id", sa.Integer, primary_key=True), sa.Column("code", sa.String(80), nullable=False), sa.Column("name", sa.String(200), nullable=False), sa.Column("description", sa.Text, nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_assets_code", "assets", ["code"], unique=True)
    op.create_index("ix_assets_name", "assets", ["name"])
    op.create_table("audit_logs", sa.Column("id", sa.Integer, primary_key=True), sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")), sa.Column("action", sa.String(80), nullable=False), sa.Column("entity", sa.String(80), nullable=False), sa.Column("entity_id", sa.String(80), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))

def downgrade():
    op.drop_table("audit_logs")
    op.drop_index("ix_assets_name", table_name="assets")
    op.drop_index("ix_assets_code", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
