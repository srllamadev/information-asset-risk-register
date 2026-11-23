import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Download } from 'lucide-react';
import { request, download } from './api';
import { validatePasswordChange } from './profile';

const roleNames={administrador:'Administrador',gestor:'Gestor de riesgos',responsable:'Responsable de activos',auditor:'Auditor',consulta:'Consulta'};
const roles=Object.keys(roleNames);

export function createAdminPages({useAuth, useApi, Header, Modal, Result, FormError}) {
  function useWrite(path, onDone, method='POST') {
    const {token}=useAuth(), client=useQueryClient();
    return useMutation({mutationFn:data=>request(path,token,{method,body:JSON.stringify(data)}),onSuccess:()=>{client.invalidateQueries();onDone?.();}});
  }
  function UserManagement(){
    const {user}=useAuth(); const [offset,setOffset]=useState(0),[editing,setEditing]=useState(null); const q=useApi(`/users?offset=${offset}&limit=25`);
    return <><Header eyebrow="ADMINISTRACIÓN" title="Usuarios y roles" description="Administra el acceso de las cuentas institucionales." action={<button className="button primary" onClick={()=>setEditing({})}><Plus size={18}/> Nuevo usuario</button>}/><section className="card panel"><p className="notice">Los roles responsable y consulta aún no tienen acceso a registros hasta definir su alcance.</p><Result query={q} empty="No hay usuarios registrados."><div className="table-wrap"><table><thead><tr><th>USUARIO</th><th>ROL</th><th>ESTADO</th><th>ÚLTIMO ACCESO</th><th></th></tr></thead><tbody>{q.data?.map(x=><tr key={x.id}><td><strong>{x.username}</strong>{x.id===user.id&&<small>Tu cuenta</small>}</td><td>{roleNames[x.role]||x.role}</td><td><span className="badge">{x.active?'Activa':'Inactiva'}</span></td><td>{x.last_login?new Date(x.last_login).toLocaleString('es'):'Sin acceso'}</td><td><button className="text-action" onClick={()=>setEditing(x)}>Editar</button></td></tr>)}</tbody></table></div></Result><div className="pagination"><button disabled={!offset} onClick={()=>setOffset(Math.max(0,offset-25))}>Anterior</button><span>Página {offset/25+1}</span><button disabled={!q.data||q.data.length<25} onClick={()=>setOffset(offset+25)}>Siguiente</button></div></section>{editing&&<Modal title={editing.id?'Editar cuenta':'Nuevo usuario'} onClose={()=>setEditing(null)}><UserForm initial={editing} onDone={()=>setEditing(null)}/></Modal>}</>;
  }
  function UserForm({initial,onDone}){
    const save=useWrite(initial.id?`/users/${initial.id}`:'/users',onDone,initial.id?'PUT':'POST');
    const {register,handleSubmit}=useForm({defaultValues:initial.id?initial:{role:'gestor',active:true}});
    function submit(values){
      if(initial.id){
        if((values.role!==initial.role||values.active!==initial.active)&&!window.confirm('Modificar el rol o estado cerrará las sesiones de esta cuenta. ¿Deseas continuar?')) return;
        save.mutate({role:values.role,active:values.active});
      } else save.mutate({username:values.username,password:values.password,role:values.role});
    }
    return <form onSubmit={handleSubmit(submit)}>{!initial.id&&<><label>Usuario<input autoComplete="off" required maxLength="100" {...register('username')}/></label><label>Contraseña inicial<input type="password" autoComplete="new-password" required minLength="12" maxLength="1024" {...register('password')}/></label><p className="muted">La contraseña debe tener al menos 12 caracteres.</p></>}<label>Rol<select {...register('role')}>{roles.map(role=><option value={role} key={role}>{roleNames[role]}</option>)}</select></label>{initial.id&&<label className="checkbox-row"><input type="checkbox" {...register('active')}/> Cuenta activa</label>}<FormError error={save.error}/><button className="button primary" disabled={save.isPending}>Guardar usuario</button></form>;
  }
  function Profile(){
    const {user,clearSession}=useAuth(), [message,setMessage]=useState(''); const {register,handleSubmit,reset}=useForm();
    const save=useWrite('/auth/change-password',()=>{reset();clearSession();});
    function submit(values){const error=validatePasswordChange(values);setMessage(error);if(!error)save.mutate({current_password:values.current_password,new_password:values.new_password});}
    return <><Header eyebrow="CUENTA" title="Mi perfil" description="Consulta tus datos y actualiza tu contraseña."/><div className="dashboard-grid"><section className="card panel"><h2>Datos de la cuenta</h2><div className="profile-field"><span>Usuario</span><strong>{user.username}</strong></div><div className="profile-field"><span>Rol</span><strong>{roleNames[user.role]||user.role}</strong></div></section><section className="card panel"><div className="panel-head"><div><h2>Cambiar contraseña</h2><p>El cambio cerrará todas tus sesiones.</p></div></div><form onSubmit={handleSubmit(submit)}><label>Contraseña actual<input type="password" autoComplete="current-password" required {...register('current_password')}/></label><label>Nueva contraseña<input type="password" autoComplete="new-password" minLength="12" required {...register('new_password')}/></label><label>Confirmar nueva contraseña<input type="password" autoComplete="new-password" minLength="12" required {...register('confirmation')}/></label>{message&&<div className="error" role="alert">{message}</div>}<FormError error={save.error}/><button className="button primary" disabled={save.isPending}>Actualizar contraseña</button></form></section></div></>;
  }
  function Audit(){
    const [offset,setOffset]=useState(0);const q=useApi(`/audit-logs?offset=${offset}&limit=25`);
    return <><Header eyebrow="TRAZABILIDAD" title="Registro de auditoría" description="Consulta las operaciones registradas por el sistema."/><section className="card panel"><Result query={q} empty="No hay eventos de auditoría."><div className="table-wrap"><table><thead><tr><th>FECHA Y HORA UTC</th><th>USUARIO ID</th><th>ACCIÓN</th><th>ENTIDAD</th><th>REGISTRO ID</th></tr></thead><tbody>{q.data?.map(x=><tr key={x.id}><td>{new Date(x.created_at).toISOString().replace('T',' ').replace('.000Z',' UTC')}</td><td>{x.user_id??'—'}</td><td>{x.action}</td><td>{x.entity}</td><td>{x.entity_id||'—'}</td></tr>)}</tbody></table></div></Result><div className="pagination"><button disabled={!offset} onClick={()=>setOffset(Math.max(0,offset-25))}>Anterior</button><span>Página {offset/25+1}</span><button disabled={!q.data||q.data.length<25} onClick={()=>setOffset(offset+25)}>Siguiente</button></div></section></>;
  }
  function Reports(){
    const {token}=useAuth(),[error,setError]=useState(''),[busy,setBusy]=useState(false);const units=useApi('/organizational-units'),categories=useApi('/asset-categories');const {register,handleSubmit,watch}=useForm({defaultValues:{type:'assets',separator:'coma',q:'',unit_id:'',status:'',asset_id:''}});const type=watch('type');
    async function submit(v){setError('');setBusy(true);try{const params=new URLSearchParams({separator:v.separator});for(const key of (v.type==='assets'?['q','unit_id','status','category']:['asset_id']))if(v[key])params.set(key,v[key]);await download(`/reports/${v.type}.csv?${params}`,token,`${v.type==='assets'?'activos':'riesgos'}.csv`);}catch(e){setError(e.message)}finally{setBusy(false)}}
    return <><Header eyebrow="EXPORTACIÓN" title="Reportes" description="Descarga información registrada en formato CSV."/><section className="card panel report-panel"><div className="panel-head"><div><h2>Configurar reporte</h2><p>Las exportaciones se registran en la auditoría.</p></div></div><form onSubmit={handleSubmit(submit)}><label>Reporte<select {...register('type')}><option value="assets">Inventario de activos</option><option value="risks">Registro de riesgos y última evaluación</option></select></label><label>Separador<select {...register('separator')}><option value="coma">Coma</option><option value="punto_coma">Punto y coma</option></select></label>{type==='assets'?<><label>Buscar por nombre o código<input {...register('q')}/></label><label>Unidad<select {...register('unit_id')}><option value="">Todas</option>{units.data?.map(x=><option value={x.id} key={x.id}>{x.name}</option>)}</select></label>{units.isError&&<FormError error={units.error}/>}<label>Categoría<select {...register('category')}><option value="">Todas</option>{categories.data?.map(x=><option value={x.name} key={x.id}>{x.name}{!x.active?' (inactiva)':''}</option>)}</select></label>{categories.isError&&<FormError error={categories.error}/>}<label>Estado<select {...register('status')}><option value="">Todos</option><option value="activo">Activo</option><option value="en_revision">En revisión</option><option value="inactivo">Inactivo</option><option value="retirado">Retirado</option></select></label></>:<label>ID de activo (opcional)<input type="number" min="1" {...register('asset_id')}/></label>}<p className="muted">El archivo se genera con UTF-8 y contiene los campos disponibles en el registro actual.</p>{error&&<div className="error" role="alert">{error}</div>}<button className="button primary" disabled={busy}><Download size={17}/>{busy?'Generando…':'Descargar CSV'}</button></form></section></>;
  }
  return {UserManagement, Profile, Audit, Reports};
}
