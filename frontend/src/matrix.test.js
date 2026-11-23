import { describe, expect, it } from 'vitest';
import { level, risksInCell } from './matrix';
describe('matriz de riesgos', () => {
  it('clasifica los límites de la metodología inicial', () => {
    expect([1,4,5,9,10,16,17,25].map(level)).toEqual(['bajo','bajo','medio','medio','alto','alto','critico','critico']);
  });
  it('distingue las coordenadas inherentes y residuales', () => {
    const risks = [{risk_id:1,inherent_likelihood:5,inherent_impact:4,residual_likelihood:2,residual_impact:3}];
    expect(risksInCell(risks,'inherent',5,4)).toHaveLength(1);
    expect(risksInCell(risks,'residual',5,4)).toHaveLength(0);
    expect(risksInCell(risks,'residual',2,3)).toHaveLength(1);
  });
});
