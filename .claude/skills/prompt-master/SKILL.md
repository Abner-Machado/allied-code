---
name: prompt-master
description: Reescreve um pedido mal formulado no pedido que o agente precisa ler, sem inventar escopo. Use em "/prompt-master", "reescreve esse pedido", "melhora esse prompt", ou quando o próprio pedido recebido estiver ambíguo o bastante para custar turnos de ida e volta. Funciona em qualquer superfície, inclusive sessão web e na nuvem, onde o mod de botão não é desenhado.
---

# Skill: prompt-master

Mesma instrução de reescrita do mod `prompt-master` (a função `instrucao()` em
`hooks/register.tsx`), em forma de skill, para as superfícies onde o mod não desenha:
sessão web, sessão na nuvem e extensão de editor.

## O que devolver

Só o pedido reescrito. Nada de comentário, introdução, nem explicação do que mudou.

## Regras da reescrita

- Mesma língua do original. Pedido em português do Brasil volta em português do Brasil.
- Preserve a intenção e todo detalhe concreto: caminho, nome de arquivo, número, mensagem
  de erro, comando.
- Não invente requisito, tecnologia, restrição nem escopo que o original não tem.
- Deixe explícito o que estava implícito: o que entregar, onde, e como saber que ficou pronto.
- Se o original for ambíguo num ponto que muda o trabalho, termine com uma linha
  `Em dúvida: <a pergunta>`. Não escolha por conta.
- Sem markdown decorativo, sem emoji, sem elogio.
- Curto. Se o original já estava bom, devolva quase igual.

## Como usar

`/prompt-master <pedido>` devolve o pedido reescrito. Leia, ajuste se quiser, e mande.

Sem argumento, reescreva o último pedido da conversa.

## Onde instalar para a sessão na nuvem

A sessão na nuvem não lê configuração de máquina nenhuma: ela lê o repositório que foi
aberto. Copie esta pasta para `.claude/skills/prompt-master/` nesse repositório e comite.
Daí `/prompt-master` existe lá.
