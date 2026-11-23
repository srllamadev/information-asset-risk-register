"""Persistent login throttling."""
from alembic import op
import sqlalchemy as sa
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("login_attempts", sa.Column("key", sa.String(64), primary_key=True), sa.Column("attempts", sa.Integer, nullable=False), sa.Column("window_started", sa.Integer, nullable=False))

def downgrade():
    op.drop_table("login_attempts")
