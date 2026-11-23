export function validatePasswordChange(values) {
  if (!values.current_password) return 'Ingresa tu contraseña actual.';
  if (!values.new_password || values.new_password.length < 12) return 'La nueva contraseña debe tener al menos 12 caracteres.';
  if (values.new_password !== values.confirmation) return 'Las contraseñas nuevas no coinciden.';
  if (values.current_password === values.new_password) return 'La nueva contraseña debe ser diferente de la actual.';
  return '';
}
