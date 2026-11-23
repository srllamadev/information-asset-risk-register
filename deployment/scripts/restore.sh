#!/bin/sh
set -eu
if [ "$#" -ne 2 ] || [ "$2" != "--confirmar" ]; then
    echo "Uso: $0 ruta-respaldo.db --confirmar" >&2
    echo "La restauración sustituye la base actual; cree un respaldo previo." >&2
    exit 2
fi
[ -f "$1" ] || { echo "No se encuentra el respaldo" >&2; exit 1; }
echo "Deteniendo backend; no debe haber otros procesos usando el volumen."
docker compose stop backend
if docker compose run --rm --no-deps -T --entrypoint python backend -m app.maintenance restore < "$1"; then
    docker compose up -d backend
    echo "Restauración completada; compruebe la salud y los datos de la aplicación."
else
    echo "Restauración fallida. El backend permanece detenido para revisión." >&2
    exit 1
fi
