import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { request } from './api';

export function createCategoryPage({useAuth,useApi,Header,Modal,Result,FormError}) {
  function Categories() {
    const {user}=useAuth(),q=useApi('/asset-categories');const [editing,setEditing]=useState(null);
    return <><Header eyebrow="CONFIGURACIÓN" title="Categorías de activos" description="Administra las categorías disponibles para el inventario." action={user.role==='administrador'&&<button className="button primary" onClick={()=>setEditing({})}><Plus size={18}/> Nueva categoría</button>}/><section className="card panel"><p className="notice">Las categorías desactivadas se conservan en los activos existentes, pero no se pueden asignar a otros activos.</p><Result query={q} empty="No hay categorías registradas. Un administrador puede agregar las que necesite la organización.">{q.data?.map(item=><div className="list-row" key={item.id}><div className="grow"><strong>{item.name}</strong></div><span className="badge">{item.active?'Activa':'Inactiva'}</span>{user.role==='administrador'&&<button className="text-action" onClick={()=>setEditing(item)}>Editar</button>}</div>)}</Result></section>{editing&&<Modal title={editing.id?'Editar categoría':'Nueva categoría'} onClose={()=>setEditing(null)}><CategoryForm initial={editing} onDone={()=>setEditing(null)}/></Modal>}</>;
  }
  function CategoryForm({initial,onDone}) {
    const {token}=useAuth(),client=useQueryClient(),{register,handleSubmit}=useForm({defaultValues:{name:'',active:true,...initial}});
    const save=useMutation({mutationFn:data=>request(initial.id?`/asset-categories/${initial.id}`:'/asset-categories',token,{method:initial.id?'PUT':'POST',body:JSON.stringify(data)}),onSuccess:()=>{client.invalidateQueries();onDone();}});
    return <form onSubmit={handleSubmit(v=>{if(initial.id&&initial.name!==v.name.trim()&&!window.confirm('Cambiar el nombre actualizará la categoría en los activos relacionados. ¿Continuar?'))return;save.mutate(v);})}><label>Nombre<input required maxLength="150" {...register('name')}/></label><label className="checkbox-row"><input type="checkbox" {...register('active')}/> Categoría activa</label><FormError error={save.error}/><button className="button primary" disabled={save.isPending}>Guardar categoría</button></form>;
  }
  return Categories;
}
