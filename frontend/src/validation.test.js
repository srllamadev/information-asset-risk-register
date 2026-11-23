import { describe, expect, it } from 'vitest';
import { assetSchema } from './validation';
describe('validación de activos', () => {
  it('rechaza nombres y códigos vacíos', () => {
    expect(assetSchema.safeParse({code:' ', name:' ', description:'', unit_id:''}).success).toBe(false);
  });
  it('normaliza el código y el nombre', () => {
    expect(assetSchema.parse({code:' A-01 ', name:' Servidor ', description:'', unit_id:''})).toEqual({code:'A-01',name:'Servidor',description:'',unit_id:''});
  });
});
