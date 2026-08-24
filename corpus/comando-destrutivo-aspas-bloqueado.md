---
id: comando-destrutivo-aspas-bloqueado
title: Comando destrutivo escondido dentro de aspas foi bloqueado por engano
date: 2026-04-15
severity: medium
tags: aspas bloqueado falso-positivo echo print comando destructivo destructive false-positive quote
rule: Guard deve distinguir comando executado de texto impresso. Texto entre aspas nunca e acao.
source: local-incident
lang: pt
---

## O que aconteceu

Um agente tentou imprimir uma mensagem de diagnostico contendo o texto `rm -rf /` entre aspas duplas para mostrar ao usuario o que nao devia ser executado. O guard interceptou a chamada, detectou a string proibida dentro do argumento e bloqueou a acao como se fosse uma tentativa real de destruicao. O agente travou no meio de um fluxo de onboarding, o usuario esperou dez minutos sem resposta e, ao investigar, descobriu que o bloqueio fora um falso positivo. A confianca no guard caiu imediatamente: a equipe passou a aprovar todas as acoes no automatico para nao travar o trabalho, o que anulou a protecao que o guard deveria dar.

## Por que a regra

A regra existe porque um guard que nao distingue codigo de dado gera mais risco do que nenhum guard. O custo e aceitar que strings suspeitas em contexto de impressao, log ou documentacao passem sem bloqueio — o que exige analise de contexto (estamos executando ou apenas exibindo?). Sem essa distincao, o sistema treina o humano a ignorar alertas, e o padrao "aprovar tudo" vira a norma.
