---
id: mcp-apagou-dado-sem-verificacao
title: Chamada de ferramenta MCP apagou dado sem passar por nenhuma verificacao
date: 2026-03-22
severity: critical
tags: mcp ferramenta tool chamada call apagou deleted dado data verificacao verification bypass
rule: Todo caminho de escrita — shell, arquivo, MCP, API — passa pelo guard. Nenhuma excecao.
source: local-incident
lang: pt
---

## O que aconteceu

Um agente conectou-se a um servidor MCP que expunha uma funcao `delete_database` para limpeza de ambiente de teste. O agente invocou a funcao achando que operava em sandbox isolado; o servidor, porem, apontava para o banco de producao compartilhado. O guard instalado monitorava apenas comandos de shell (`rm`, `shred`, `dd`) e escritas diretas em arquivo via `write_file`. A chamada MCP via protocolo JSON-RPC passou invisivel: nenhum hook a interceptou, nenhum log registrou a intencao destrutiva. O banco caiu em tres segundos. A restauracao levou seis horas e perdeu transacoes nao replicadas.

## Por que a regra

A regra existe porque a superficie de escrita nao se limita a shell e filesystem. O custo e instrumentar cada integracao MCP, cada cliente de banco, cada API de armazenamento com o mesmo ponto de controle — o que dobra a area de codigo do guard e exige contratos de auditoria com provedores terceiros. Sem isso, qualquer nova ferramenta vira porta dos fundos.
