import { afterEach, describe, expect, it, vi } from 'vitest';
import { download } from './api';

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
describe('descarga de reportes', () => {
  it('envía el token y descarga el CSV recibido', async () => {
    vi.useFakeTimers();
    const fetchMock=vi.fn().mockResolvedValue({ok:true,blob:async()=>new Blob(['datos'])});
    const link={click:vi.fn(),remove:vi.fn()};
    const createObjectURL=vi.fn().mockReturnValue('blob:test'),revokeObjectURL=vi.fn();
    vi.stubGlobal('fetch',fetchMock);
    vi.stubGlobal('URL',{createObjectURL,revokeObjectURL});
    vi.stubGlobal('document',{createElement:()=>link,body:{appendChild:vi.fn()}});
    await download('/reports/assets.csv?separator=coma','token-de-prueba','activos.csv');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/reports/assets.csv?separator=coma',{headers:{Authorization:'Bearer token-de-prueba'}});
    expect(link.download).toBe('activos.csv');
    expect(link.click).toHaveBeenCalledOnce();
    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:test');
  });
  it('no descarga y comunica errores de autorización', async () => {
    const event=vi.fn();
    vi.stubGlobal('window',{dispatchEvent:event});
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:false,status:401,json:async()=>({detail:'Sesión inválida'})}));
    await expect(download('/reports/assets.csv','token-de-prueba','activos.csv')).rejects.toThrow('Sesión inválida');
    expect(event).toHaveBeenCalledOnce();
  });
});
