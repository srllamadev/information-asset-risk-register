#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then echo "Uso: $0 ruta-respaldo.db" >&2; exit 2; fi
umask 077
output=$1
if [ -e "$output" ]; then echo "El archivo de destino ya existe" >&2; exit 1; fi
partial="${output}.partial.$$"
trap 'rm -f "$partial"' EXIT HUP INT TERM
docker compose exec -T backend python -m app.maintenance backup > "$partial"
[ -s "$partial" ] || { echo "El respaldo está vacío" >&2; exit 1; }
mv -n "$partial" "$output"
[ ! -e "$partial" ] || { echo "No se pudo guardar sin sobrescribir" >&2; exit 1; }
echo "Respaldo creado: $output"
