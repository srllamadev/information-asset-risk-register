export const level = n => n <= 4 ? 'bajo' : n <= 9 ? 'medio' : n <= 16 ? 'alto' : 'critico';
export const risksInCell = (risks, mode, probability, impact) => risks.filter(risk => risk[`${mode}_likelihood`] === probability && risk[`${mode}_impact`] === impact);
