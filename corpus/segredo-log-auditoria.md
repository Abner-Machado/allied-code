---
id: segredo-log-auditoria
title: Segredo foi parar no log de auditoria
date: 2026-07-18
severity: critical
tags: segredo secret token chave key log auditoria audit vazamento leak credencial credential
rule: Log de auditoria nunca grava argumentos brutos. Sanitiza token, chave, senha antes de persistir.
source: local-incident
lang: pt
---

## O que aconteceu

O guard registrava cada decisao em um log de auditoria estruturado: acao, parametros, resultado, assinatura do agente. Para chamadas de API, o sistema serializava o payload completo da requisicao no campo `arguments`. Uma aprovacao de rotina para rotacionar credenciais incluiu o novo token de acesso no corpo da requisicao. O log gravou o token em texto plano. O arquivo de auditoria era replicado para bucket de analise acessivel a estagiarios. Tres dias depois, um estagiario usou o token valido para acessar o painel de faturamento. A rotacao teve que ser refeita as pressas e o bucket foi isolado.

## Por que a regra

A regra existe porque o log de auditoria costuma ter retencao longa, replicacao ampla e acesso menos restrito que o proprio segredo. O custo e implementar sanitizacao contextual em todo ponto de logging: detectar campos sensiveis por nome (`token`, `secret`, `password`, `api_key`, `authorization`) e por padrao (JWT, chave SSH, AWS key), substituir por hash ou mascara antes de gravar — o que adiciona overhead em cada escrita de log, exige lista de padroes atualizada e pode mascarar dados uteis para debugging legitimo. Sem sanitizacao, o log vira o vetor de vazamento.
