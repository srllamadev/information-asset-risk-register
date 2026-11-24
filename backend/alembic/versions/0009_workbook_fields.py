"""Represent workbook fields and permit a pending residual evaluation."""
from alembic import op
import sqlalchemy as sa
revision='0009'
down_revision='0008'
branch_labels=None
depends_on=None

asset_fields=[('macroprocess',sa.String(200)),('subprocess',sa.String(200)),('administrator',sa.String(200)),('authorized_users',sa.Text()),('supplier',sa.String(200)),('criticality_justification',sa.Text()),('evidence',sa.Text()),('evidence_status',sa.String(100)),('source_reference',sa.Text()),('normative_reference',sa.Text())]
risk_fields=[('code',sa.String(80)),('affected_process',sa.String(200)),('evidence_status',sa.String(100)),('evidence_reference',sa.Text()),('proposed_treatment',sa.Text())]
control_fields=[('implementation_date',sa.String(10)),('verification_date',sa.String(10)),('verified_effectiveness',sa.String(100)),('verification_result',sa.Text()),('observations',sa.Text())]

def upgrade():
    for name,kind in asset_fields: op.add_column('assets',sa.Column(name,kind,nullable=True))
    for name,kind in risk_fields: op.add_column('risk_scenarios',sa.Column(name,kind,nullable=True))
    op.create_index('ix_risk_scenarios_code','risk_scenarios',['code'],unique=True)
    for name,kind in control_fields: op.add_column('security_controls',sa.Column(name,kind,nullable=True))
    with op.batch_alter_table('risk_assessments') as batch:
        batch.add_column(sa.Column('source_assessed_date',sa.Date(),nullable=True))
        batch.alter_column('residual_likelihood',existing_type=sa.Integer(),nullable=True)
        batch.alter_column('residual_impact',existing_type=sa.Integer(),nullable=True)
        batch.create_check_constraint('ck_risk_residual_pair','(residual_likelihood IS NULL AND residual_impact IS NULL) OR (residual_likelihood IS NOT NULL AND residual_impact IS NOT NULL)')

def downgrade():
    # Downgrading is unsafe while pending residuals exist; do not silently invent values.
    conn=op.get_bind()
    if conn.execute(sa.text('SELECT count(*) FROM risk_assessments WHERE residual_likelihood IS NULL OR residual_impact IS NULL')).scalar():
        raise RuntimeError('No se puede revertir: existen evaluaciones residuales pendientes')
    with op.batch_alter_table('risk_assessments') as batch:
        batch.drop_constraint('ck_risk_residual_pair',type_='check')
        batch.drop_column('source_assessed_date')
        batch.alter_column('residual_likelihood',existing_type=sa.Integer(),nullable=False)
        batch.alter_column('residual_impact',existing_type=sa.Integer(),nullable=False)
    for name,_ in reversed(control_fields): op.drop_column('security_controls',name)
    op.drop_index('ix_risk_scenarios_code',table_name='risk_scenarios')
    for name,_ in reversed(risk_fields): op.drop_column('risk_scenarios',name)
    for name,_ in reversed(asset_fields): op.drop_column('assets',name)
