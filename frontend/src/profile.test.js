import { describe, it, expect } from 'vitest';
import { validatePasswordChange } from './profile';
describe('cambio de contraseña',()=>{
  it('exige una contraseña nueva larga y coincidente',()=>{
    expect(validatePasswordChange({current_password:'anterior',new_password:'corta',confirmation:'corta'})).toContain('12');
    expect(validatePasswordChange({current_password:'anterior',new_password:'nueva clave larga',confirmation:'diferente'})).toContain('coinciden');
  });
  it('rechaza la contraseña anterior y acepta una nueva válida',()=>{
    expect(validatePasswordChange({current_password:'misma clave larga',new_password:'misma clave larga',confirmation:'misma clave larga'})).toContain('diferente');
    expect(validatePasswordChange({current_password:'anterior',new_password:'nueva clave larga',confirmation:'nueva clave larga'})).toBe('');
  });
});
