"""Preview and atomically import the institutional workbook format."""
import base64
import binascii
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .db import get_db
from .main import METHODOLOGY_V1, current_user, require_role
from .models import Asset, AssetAssessment, AssetCategory, AssetDependency, AuditLog, OrganizationalUnit, RiskAssessment, RiskControl, RiskScenario, SecurityControl, Threat, User, Vulnerability

router=APIRouter(prefix='/api/v1/imports')
NS={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main','r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
HEADERS={
 'Inventario':['ID','Nombre del activo','Categoría','Tipo de activo','Descripción y finalidad','Macroproceso','Proceso','Subproceso o actividad','Propietario','Custodio','Administrador','Usuarios autorizados','Ubicación','Proveedor o tercero','Dependencias (ID)','Confidencialidad (1–5)','Integridad (1–5)','Disponibilidad (1–5)','Criticidad preliminar','Justificación de criticidad','Evidencia / referencia documental','Estado de evidencia','Fuente o sección','Fecha de revisión','Área / unidad responsable','Clasificación de información','Ciclo de vida','Referencia normativa'],
 'Riesgos':['ID riesgo','ID activo','Activo asociado (auto)','Amenaza / fuente','Vulnerabilidad','Escenario y consecuencia','Proceso afectado','Probabilidad (1–5)','Impacto (1–5)','Riesgo inherente (auto)','Nivel inherente (auto)','Controles existentes','Prob. residual (1–5)','Impacto residual (1–5)','Riesgo residual (auto)','Nivel residual (auto)','Tratamiento propuesto','Dueño del riesgo','Fecha de evaluación','Estado de evidencia','Evidencia / fundamento'],
 'Controles':['ID control','ID riesgo','ID activo (auto)','Control / salvaguarda','Tipo de control','Referencia de control','Responsable','Estado de implementación','Fecha de implementación','Evidencia del control','Fecha de verificación','Eficacia verificada','Resultado de verificación','Próxima revisión','Estado de registro (auto)','Observaciones']}


def excel_column(index):
    result=''
    while index:
        index,rem=divmod(index-1,26)
        result=chr(65+rem)+result
    return result

class WorkbookInput(BaseModel):
    content_base64: str = Field(max_length=7_000_000)


def read_xml(z, name):
    raw=z.read(name)
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('El archivo contiene declaraciones XML no admitidas')
    return ET.fromstring(raw)


def parse_workbook(value):
    try:
        raw=base64.b64decode(value,validate=True)
        if len(raw)>5_000_000:
            raise ValueError('El archivo supera 5 MB')
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            entries=z.infolist()
            if len(entries)>300 or sum(i.file_size for i in entries)>30_000_000:
                raise ValueError('El contenido descomprimido supera el límite permitido')
            if any(i.flag_bits & 1 for i in entries) or any(i.filename.endswith('vbaProject.bin') for i in entries):
                raise ValueError('No se admiten archivos cifrados o con macros')
            wb=read_xml(z,'xl/workbook.xml'); rel=read_xml(z,'xl/_rels/workbook.xml.rels')
            paths={r.attrib['Id']:r.attrib['Target'].lstrip('/') for r in rel}
            strings=[]
            if 'xl/sharedStrings.xml' in z.namelist():
                strings=[''.join(t.text or '' for t in x.findall('.//m:t',NS)) for x in read_xml(z,'xl/sharedStrings.xml').findall('m:si',NS)]
            result={}
            for sheet in wb.findall('m:sheets/m:sheet',NS):
                name=sheet.attrib['name']
                if name not in HEADERS: continue
                target=paths[sheet.attrib['{'+NS['r']+'}id']]
                target=target if target.startswith('xl/') else 'xl/'+target
                if not target.startswith('xl/worksheets/') or '..' in target:
                    raise ValueError('Ruta de hoja no válida')
                rows=[]
                header={}
                for row in read_xml(z,target).findall('.//m:sheetData/m:row',NS):
                    number=int(row.attrib['r'])
                    if number<7: continue
                    cells={}
                    for c in row.findall('m:c',NS):
                        match=re.fullmatch(r'([A-Z]{1,3})[0-9]+',c.attrib.get('r',''))
                        if not match: continue
                        col=match.group(1); v=c.find('m:v',NS); kind=c.attrib.get('t'); value=(v.text or '') if v is not None else ''
                        if kind=='s' and value: value=strings[int(value)]
                        if kind=='inlineStr': value=''.join(t.text or '' for t in c.findall('.//m:t',NS))
                        if c.find('m:f',NS) is not None: value=None
                        cells[col]=value
                    if number==7: header=cells
                    elif cells.get('A'): rows.append((number,cells))
                if any(header.get(excel_column(i)) != expected for i,expected in enumerate(HEADERS[name],1)): raise ValueError(f'Encabezados inesperados en {name}; utilice la plantilla indicada')
                if len(rows)>1000: raise ValueError(f'Demasiados registros en {name}')
                result[name]=rows
            if set(result)!=set(HEADERS): raise ValueError('Se requieren las hojas Inventario, Riesgos y Controles')
            return result
    except (zipfile.BadZipFile, KeyError, IndexError, ET.ParseError, binascii.Error, UnicodeError) as exc:
        raise ValueError('Archivo XLSX inválido o no compatible') from exc


def text(row,col):
    value=row.get(col,'')
    if value is None: raise ValueError(f'La columna {col} no puede contener fórmulas')
    return str(value or '').strip()


def number(row,col,optional=False):
    value=text(row,col)
    if not value and optional:return None
    if value not in {'1','2','3','4','5'}:raise ValueError(f'La columna {col} debe ser un entero de 1 a 5')
    return int(value)


def day(row,col):
    value=text(row,col)
    if not value:return None
    try:
        if re.fullmatch(r'\d+(\.0+)?',value): return (date(1899,12,30)+timedelta(days=int(float(value))))
        return date.fromisoformat(value[:10])
    except (ValueError,OverflowError): raise ValueError(f'Fecha inválida en columna {col}') from None


def validate(rows,db):
    errors=[]; codes={};warnings=['Las fórmulas de Excel se ignoran; los valores se recalculan con la metodología vigente.', 'Los datos y escenarios del archivo deben revisarse; las fuentes públicas no acreditan vulnerabilidades ni controles.']
    for sheet in HEADERS:
        seen=set()
        for n,row in rows[sheet]:
            try:
                code=text(row,'A')
                if not code or len(code)>80:raise ValueError('ID vacío o mayor a 80 caracteres')
                if code in seen:raise ValueError(f'ID duplicado: {code}')
                seen.add(code)
                input_columns={'Inventario':'ABCDEFGHIJKLMNOPQRTUVWXYZ','Riesgos':'ABDEFGHILMNQRSTU','Controles':'ABDEFGHIJKLMNP'}[sheet]
                for col in input_columns:
                    if len(text(row,col))>5000:raise ValueError(f'Columna {col} supera 5000 caracteres')
                if sheet=='Inventario':
                    if not text(row,'B') or len(text(row,'B'))>200:raise ValueError('Nombre de activo inválido')
                    for col in 'PQR':number(row,col)
                    day(row,'X')
                    lifecycle=text(row,'AA').casefold()
                    if lifecycle and lifecycle not in {'activo','en revisión','inactivo','retirado'}:raise ValueError('Estado de activo no admitido')
                    for col,limit in {'C':150,'D':100,'F':200,'G':200,'H':200,'I':200,'J':200,'K':200,'M':200,'N':200,'Y':200,'Z':100,'V':100}.items():
                        if len(text(row,col))>limit:raise ValueError(f'Columna {col} supera {limit} caracteres')
                    text(row,'AA');text(row,'AB')
                elif sheet=='Riesgos':
                    for col in ('B','D','E','F','R'):
                        if not text(row,col):raise ValueError(f'Falta la columna {col}')
                    if len(text(row,'D'))>200 or len(text(row,'E'))>200 or len(text(row,'R'))>200:raise ValueError('Amenaza, vulnerabilidad o responsable excede 200 caracteres')
                    number(row,'H');number(row,'I');a=number(row,'M',True);b=number(row,'N',True)
                    if (a is None)!=(b is None):raise ValueError('El residual requiere probabilidad e impacto o ambos vacíos')
                    day(row,'S')
                else:
                    if not text(row,'B') or not text(row,'D'):raise ValueError('Falta ID de riesgo o nombre del control')
                    for col,limit in {'D':200,'E':100,'F':200,'G':200,'H':100,'L':100}.items():
                        if len(text(row,col))>limit:raise ValueError(f'Columna {col} supera {limit} caracteres')
                    for col in ('I','K','N'):day(row,col)
            except ValueError as exc:errors.append(f'{sheet}, fila {n}: {exc}')
        codes[sheet]=seen
    existing_assets=set(db.scalars(select(Asset.code)).all());existing_risks=set(db.scalars(select(RiskScenario.code).where(RiskScenario.code.is_not(None))).all());existing_controls=set(db.scalars(select(SecurityControl.code)).all())
    for sheet,existing in [('Inventario',existing_assets),('Riesgos',existing_risks),('Controles',existing_controls)]:
        for code in sorted(codes[sheet]&existing):errors.append(f'{sheet}: el código {code} ya existe')
    for n,r in rows['Inventario']:
        for dep in text(r,'O').split(';'):
            dep=dep.strip()
            if dep and dep not in codes['Inventario'] and dep not in existing_assets:errors.append(f'Inventario, fila {n}: dependencia {dep} inexistente')
            if dep and dep==text(r,'A'):errors.append(f'Inventario, fila {n}: dependencia a sí mismo')
    for n,r in rows['Riesgos']:
        if text(r,'B') not in codes['Inventario'] and text(r,'B') not in existing_assets:errors.append(f'Riesgos, fila {n}: activo {text(r,"B")} inexistente')
    for n,r in rows['Controles']:
        if text(r,'B') not in codes['Riesgos'] and text(r,'B') not in existing_risks:errors.append(f'Controles, fila {n}: riesgo {text(r,"B")} inexistente')
    inactive=set(db.scalars(select(AssetCategory.name).where(AssetCategory.active.is_(False))).all())
    for n,r in rows['Inventario']:
        if text(r,'C') in inactive: errors.append(f'Inventario, fila {n}: categoría inactiva {text(r,"C")}')
    if any(r.get('M','')=='' and r.get('N','')=='' for _,r in rows['Riesgos']):warnings.append('Los residuales vacíos se conservarán como pendientes; no se calculará una reducción.')
    existing_names={a.name.casefold().replace('ejercicio — ','').strip() for a in db.scalars(select(Asset)).all()}
    possible=[text(r,'A') for _,r in rows['Inventario'] if text(r,'B').casefold().strip() in existing_names]
    if possible:warnings.append('Posibles activos ya registrados con otro código: '+', '.join(possible)+'. Revise antes de confirmar.')
    return errors,warnings


def parse_and_check(data,db):
    try:
        rows=parse_workbook(data.content_base64)
        errors,warnings=validate(rows,db)
        return rows,errors,warnings
    except ValueError as exc: raise HTTPException(422,str(exc)) from None

@router.post('/workbook/preview')
def preview(data: WorkbookInput, user: User=Depends(current_user), db: Session=Depends(get_db)):
    require_role(user,{'administrador'})
    rows,errors,warnings=parse_and_check(data,db)
    return {'valid':not errors,'counts':{name:len(items) for name,items in rows.items()},'errors':errors[:100],'warnings':warnings}


def get_or_create(db,model,name,**kwargs):
    obj=db.scalar(select(model).where(model.name==name))
    if obj is None:
        obj=model(name=name,**kwargs);db.add(obj);db.flush()
    return obj

@router.post('/workbook', status_code=201)
def import_workbook(data: WorkbookInput, user: User=Depends(current_user), db: Session=Depends(get_db)):
    require_role(user,{'administrador'})
    rows,errors,warnings=parse_and_check(data,db)
    if errors: raise HTTPException(422, {'message':'El archivo contiene errores; revise la vista previa','errors':errors[:100]})
    assets={x.code:x for x in db.scalars(select(Asset)).all()};risks={x.code:x for x in db.scalars(select(RiskScenario).where(RiskScenario.code.is_not(None))).all()}
    try:
        for _,r in rows['Inventario']:
            unit=get_or_create(db,OrganizationalUnit,text(r,'Y')) if text(r,'Y') else None
            if text(r,'C'):get_or_create(db,AssetCategory,text(r,'C'),active=True)
            asset=Asset(code=text(r,'A'),name=text(r,'B'),category=text(r,'C') or None,asset_type=text(r,'D') or None,description=text(r,'E'),macroprocess=text(r,'F') or None,process=text(r,'G') or None,subprocess=text(r,'H') or None,owner=text(r,'I') or None,custodian=text(r,'J') or None,administrator=text(r,'K') or None,authorized_users=text(r,'L') or None,location=text(r,'M') or None,supplier=text(r,'N') or None,criticality_justification=text(r,'T') or None,evidence=text(r,'U') or None,evidence_status=text(r,'V') or None,source_reference=text(r,'W') or None,review_date=day(r,'X'),unit_id=unit.id if unit else None,classification=text(r,'Z') or None,normative_reference=text(r,'AB') or None,observations='Importado desde Excel; valoraciones de origen sujetas a revisión.')
            lifecycle=text(r,'AA').casefold(); statuses={'activo':'activo','en revisión':'en_revision','inactivo':'inactivo','retirado':'retirado'}
            if lifecycle and lifecycle not in statuses: raise ValueError(f'Estado de activo no admitido: {lifecycle}')
            asset.status=statuses.get(lifecycle,'activo'); db.add(asset);db.flush();assets[asset.code]=asset
            reason=text(r,'T') or 'El archivo no contiene justificación de la valoración.'
            reason='Justificación general proporcionada en el archivo; evaluación importada, no atribuida al importador: '+reason
            db.add(AssetAssessment(asset_id=asset.id,confidentiality=number(r,'P'),integrity=number(r,'Q'),availability=number(r,'R'),confidentiality_reason=reason,integrity_reason=reason,availability_reason=reason,assessor_id=user.id))
        db.flush()
        for _,r in rows['Inventario']:
            for dep in {x.strip() for x in text(r,'O').split(';') if x.strip()}:
                db.add(AssetDependency(asset_id=assets[text(r,'A')].id,depends_on_id=assets[dep].id))
        for _,r in rows['Riesgos']:
            threat=get_or_create(db,Threat,text(r,'D'),description='Origen: hoja Riesgos del archivo importado.',category='Importación',active=True)
            vulnerability=get_or_create(db,Vulnerability,text(r,'E'),description='Origen: hoja Riesgos del archivo importado; verificar antes de asumir que es real.',category='Importación',active=True)
            risk=RiskScenario(code=text(r,'A'),asset_id=assets[text(r,'B')].id,threat_id=threat.id,vulnerability_id=vulnerability.id,event=text(r,'D'),causes='No especificadas en el archivo.',consequences=text(r,'F'),owner=text(r,'R'),affected_process=text(r,'G') or None,evidence_status=text(r,'T') or None,evidence_reference=text(r,'U') or None,proposed_treatment=text(r,'Q') or None)
            db.add(risk);db.flush();risks[risk.code]=risk
            db.add(RiskAssessment(risk_id=risk.id,inherent_likelihood=number(r,'H'),inherent_impact=number(r,'I'),residual_likelihood=number(r,'M',True),residual_impact=number(r,'N',True),existing_controls=text(r,'L') or 'No especificados en el archivo.',effectiveness='No evaluada en el archivo.',justification='Datos importados del archivo. Fundamento: '+(text(r,'U') or 'No proporcionado.'),source_assessed_date=day(r,'S'),methodology=METHODOLOGY_V1,assessor_id=user.id))
        db.flush()
        for _,r in rows['Controles']:
            control=SecurityControl(code=text(r,'A'),name=text(r,'D'),description='Registro importado de la hoja Controles.',source='Referencias indicadas en el archivo, pendientes de verificación.',reference=text(r,'F'),control_type=text(r,'E'),implementation_status=text(r,'H'),owner=text(r,'G'),evidence=text(r,'J'),implementation_date=day(r,'I').isoformat() if day(r,'I') else None,verification_date=day(r,'K').isoformat() if day(r,'K') else None,verified_effectiveness=text(r,'L') or None,verification_result=text(r,'M') or None,review_date=day(r,'N').isoformat() if day(r,'N') else None,observations=text(r,'P') or None)
            db.add(control);db.flush();db.add(RiskControl(risk_id=risks[text(r,'B')].id,control_id=control.id))
        db.add(AuditLog(user_id=user.id,action='importar',entity='libro_xlsx',entity_id=''))
        db.commit()
    except (IntegrityError, ValueError, KeyError) as exc:
        db.rollback()
        raise HTTPException(409, 'No se importó ningún registro: revise duplicados, estados y referencias') from exc
    return {'counts':{name:len(items) for name,items in rows.items()},'warnings':warnings}
