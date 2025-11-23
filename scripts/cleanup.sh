#!/bin/bash

echo "=== Limpeza do Ambiente ==="

echo "1. Parando todos os containers..."
docker compose down

echo "2. Removendo volumes (CUIDADO: dados serão perdidos)..."
read -p "Deseja remover todos os volumes? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker compose down -v
    docker volume prune -f
    echo "✅ Volumes removidos"
fi

echo "3. Removendo containers órfãos..."
docker compose down --remove-orphans

echo "4. Limpando imagens não utilizadas..."
docker image prune -f

echo "✅ Limpeza concluída!"
