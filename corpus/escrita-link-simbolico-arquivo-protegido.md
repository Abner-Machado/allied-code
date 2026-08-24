---
id: escrita-link-simbolico-arquivo-protegido
title: Escrita passou por link simbolico e alterou arquivo protegido
date: 2026-02-28
severity: high
tags: link-simbolico symlink symlink arquivo-protegido protected-file segredo secret traversal
rule: Guard resolve caminho canonico antes de autorizar escrita. Nao confia no caminho informado.
source: local-incident
lang: pt
---

## O que aconteceu

Um agente recebeu instrucao para gravar um relatorio temporario em `./tmp/report.json`. O caminho parecia inofensivo e dentro do workspace. O guard validou o prefixo `./tmp/` e autorizou. O que o guard nao viu: `./tmp/` era um link simbolico apontando para `/etc/app/secrets/`, diretorio que continha chaves de API e certificados TLS. A escrita sobrescreveu `secrets.yaml` com JSON invalido, derrubando a validacao de assinatura de todos os servicos downstream. A falha so foi detectada quando deployments comecaram a falhar em cascata trinta minutos depois.

## Por que a regra

A regra existe porque o filesystem mente — symlinks, mount binds, junction points no Windows, hardlinks todos separam caminho logico de alvo fisico. O custo e resolver todo caminho para seu inode real (ou equivalentemente canonico) antes de checar politicas, o que exige chamada de sistema extra por operacao, trata race conditions (TOCTOU) e complica suporte a sistemas de arquivo remotos. Sem resolucao canonica, qualquer link vira bypass.
