# Allied Code — integrações

Este documento cobre as três camadas em que o corpus de incidentes é consultado,
como manter esse corpus dentro de um vault do Obsidian, como entregá-lo a outro
modelo, e o que ainda **não** existe.

O código, a CLI e o restante da documentação estão em inglês. Esta página está em
português porque é onde as decisões de integração precisam ser entendidas antes
de serem copiadas, e material sobre proteção de agentes praticamente não existe
em português.

---

## Antes de tudo: isto resolve um problema real?

Cada peça abaixo passou por uma pergunta única — *uma pessoa real, com problemas
reais, resolve pelo menos 30% deles com isso?* Duas reprovaram e estão marcadas
como tal, porque uma seção honesta sobre o que não funciona vale mais do que uma
lista de recursos.

| Peça | Resolve? | Para quem, e o quanto |
| --- | --- | --- |
| Instalação em um comando | **Sim** | Quem já tentou ligar um hook na mão. Era `git clone` mais `PYTHONPATH` mais colar JSON; virou `pipx install` mais `guard install --write`. Não é um recurso: é a diferença entre usar e desistir na primeira noite. |
| Injeção no início da tarefa | **Sim** | Quem trabalha com agente que propõe planos. Bloquear o comando no fim resolve o comando; injetar o precedente no começo resolve o plano que geraria o comando. |
| Corpus dentro do Obsidian | **Sim, para quem já tem vault** | Se você não mantém notas, isso não muda nada. Se mantém, o corpus deixa de ser mais uma pasta órfã que envelhece sem ninguém abrir. |
| Briefing para outro modelo | **Parcial** | Útil para quem delega tarefa a subagente. Sozinho não resolve 30% de nada — é encanamento para o item acima. |
| Camada de MCP de vídeo | **Não — não existe** | Documentada abaixo como risco mapeado e não implementado. Não conte com ela. |
| Corpus em português | **Não ainda** | Limitação medida, com número, na seção *Limites honestos*. É o problema mais sério desta lista para quem trabalha em português. |

---

## Instalação

Requer Python 3.11 ou superior. Nenhuma dependência.

```bash
pipx install git+https://github.com/Abner-Machado/allied-code
guard install --write        # escreve os hooks no settings do agente
guard doctor                 # confirma que ficou de pé
```

O `--write` faz backup do arquivo com data e hora antes de tocar nele, mescla em
vez de substituir, e não duplica se você rodar duas vezes. Sem `--write`, o
comando apenas imprime o bloco para você colar. Esse cuidado não é zelo genérico:
o próprio corpus registra o incidente `config-edit-broke-working-tooling`, em que
editar uma configuração global para instalar uma ferramenta quebrou a ferramenta
que já funcionava.

O `guard doctor` responde a única pergunta que importa depois de instalar —
*está ligado de verdade?* Ele verifica versão do Python, corpus encontrado,
ledger gravável, classificação funcionando e hook presente no arquivo de
configuração. Sai com código 1 se algo falhar.

Modo padrão é `observe`: classifica, recupera e registra, mas nunca bloqueia.
Rode assim por uma semana, leia `guard stats` e só então mude para `enforce`.

---

## As três camadas

O corpus é o mesmo nos três pontos. O que muda é o instante em que ele chega.

| Camada | Evento | Quando dispara | O que pode fazer |
| --- | --- | --- | --- |
| Regras permanentes | `SessionStart` | Ao abrir a sessão | Injeta as regras de severidade crítica. Custo pago uma vez. |
| Precedente da tarefa | `UserPromptSubmit` | Quando a tarefa é descrita | Injeta os incidentes parecidos com o pedido, antes de o plano existir. |
| Guarda de execução | `PreToolUse` | Antes de cada chamada de ferramenta | Devolve `deny`, `ask` ou `defer`. É a única que interrompe. |

Elas não são redundantes, e instalar só a última é o erro comum. Quando o
`PreToolUse` vê o comando, o plano já foi escrito e o raciocínio que o produziu já
foi gasto — o guarda só consegue discutir com uma decisão pronta. A injeção no
início muda o que é proposto; o bloqueio no fim só impede o que foi proposto.

### O que a injeção pode e não pode escrever

A camada de injeção escreve dentro do prompt, então tem três limites duros:

1. **Só emite texto lido da pasta do corpus.** Nada é sintetizado, nada é buscado
   na rede, nenhum outro arquivo do disco é elegível. O corpus é, por definição,
   escrito pelo dono da máquina — é essa fronteira, e só ela, que torna aceitável
   escrever no prompt.
2. **É limitada em tamanho.** Teto de 1200 caracteres e três incidentes. Injeção
   que cresce junto com o corpus vira imposto cobrado em todo turno, e a primeira
   coisa que se faz com um imposto desses é desinstalar quem cobra.
3. **Falha em silêncio.** Sem corpus, JSON inválido, arquivo ilegível: não emite
   nada. A sessão não deve conseguir distinguir "sem precedente" de "guarda
   quebrado" — essa diferença aparece no ledger, não no prompt.

### Duas portas para relevância

A injeção exige **duas** condições, não uma: o score de recuperação e o
vocabulário. O motivo está registrado no corpus, em
`threshold-silently-disabled-a-layer`.

O score é normalizado pelo peso da consulta inteira, então só é comparável entre
consultas de tamanho parecido. Medido neste corpus, uma mesma intenção pontua
0,446 escrita como comando, 0,398 como frase curta e 0,219 como a frase que uma
pessoa realmente digita. Um piso calibrado em comandos, aplicado a prompts, não
filtra: desliga.

Baixar o piso resolveu o silêncio e criou ruído — "renomear uma variável local
num arquivo de teste" passou a trazer três incidentes por palavras genéricas em
comum. A correção que ficou de pé foi somar uma segunda porta: o pedido precisa
usar pelo menos uma palavra da linha `tags` do incidente, que é a única parte
escolhida a dedo por um humano. O score diz "parecido o bastante"; as tags dizem
"sobre o mesmo assunto".

---

## Corpus dentro do Obsidian

Um incidente é um arquivo markdown com front matter YAML. Isso não é coincidência
de formato: é o formato do Obsidian, do Logseq, do Foam e de qualquer editor de
notas em texto puro. Aponte o corpus para uma pasta do vault e pronto:

```toml
# guard.toml
[guard]
corpus_dir = "~/Obsidian Vault/Operações/Incidentes"
mode = "observe"
```

Ou por variável de ambiente, sem arquivo de configuração:

```bash
GUARD_CORPUS="~/Obsidian Vault/Operações/Incidentes" guard brief "rotacionar as chaves"
```

O ganho não é técnico, é de manutenção. Corpus em pasta separada é corpus que
ninguém abre; ele envelhece, para de refletir a máquina, e o guarda passa a citar
precedente velho com a mesma confiança de antes. Dentro do vault, o incidente
está onde a pessoa já escreve, aparece nas buscas dela e no grafo, e pode ser
ligado às notas do projeto com `[[wikilinks]]` normais — o corpo do incidente não
é interpretado como código, então links, callouts e imagens não atrapalham a
recuperação.

**Bug corrigido nesta versão.** O leitor de front matter só entendia o formato
que este projeto escreve. As duas formas de lista que o Obsidian escreve
chegavam quebradas: `tags: [a, b]` virava `[a` e `b]`, e a lista em bloco
(`- a` em linhas separadas, que é o padrão do editor) resultava em **nenhuma
tag**. O documento continuava carregando e todos os campos visíveis continuavam
certos — o que sumia era exatamente o vocabulário escrito à mão para o incidente
ser encontrado. A recuperação piorava em silêncio. Está corrigido, com cinco
testes cobrindo os formatos, e registrado em `vault-front-matter-dropped-tags`.

Escreva um incidente novo direto do terminal, sem abrir o editor:

```bash
guard learn --id chave-orfa \
  --title "Formulário reenviado criou credencial duplicada" \
  --rule "Confirmar o resultado antes de repetir a submissão" \
  --severity high --tags credencial formulario automacao
```

---

## Entregando o corpus a outro modelo

O mesmo corpus atende dois leitores. `guard check` responde "isto deveria rodar?",
um comando por vez. `guard brief` responde "o que quem vai fazer isto precisa
saber antes?" — a mesma evidência, entregue antes do trabalho em vez de durante.

Para orquestração, `brief --json` é o formato de entrega ao subagente:

```bash
guard brief "publicar release no GitHub" --json
```

```json
[{"id":"published-under-the-wrong-identity","score":0.61,"severity":"high",
  "rule":"Nada que sai para fora vai antes de a destinação ser dita de volta e confirmada...",
  "title":"A release went out under the wrong account"}]
```

O padrão de uso é injetar isso no prompt do subagente antes de delegar. Um
subagente começa frio: não viu os erros que a máquina já cometeu, e vai repeti-los
com confiança. As regras vão como texto; o `id` serve para o orquestrador
verificar depois se o subagente foi avisado de algo que mesmo assim aconteceu.

Uma advertência de escopo: isso é encanamento, não solução. Sozinho, entregar
regras a um subagente não garante que ele as siga. O que fecha o ciclo é o
`PreToolUse` continuar ligado enquanto o subagente trabalha.

---

## Limites honestos

**Idioma. Este é o limite mais sério.** A recuperação é lexical: casa vocabulário,
não significado. Um corpus escrito em inglês não responde a um pedido em
português. Medido neste corpus:

| Consulta | Score |
| --- | --- |
| `delete tooling` | 0,744 |
| `apagar ferramentas instaladas` | 0,000 |

Mesma intenção, mesmo incidente, e o pedido em português não recupera nada — sem
erro, sem aviso. Se você trabalha em português, **escreva o corpus em português**,
ou aceite que as camadas de injeção ficarão mudas. Misturar os dois idiomas no
mesmo corpus funciona, mas cada incidente só é recuperado no idioma em que foi
escrito. Tradução automática do corpus não está implementada e não deve ser
presumida.

**Classificação é regex sobre a string do comando.** Ofuscação derrota
trivialmente. Isto é proteção contra acidente e automação confiante demais, não
contra adversário com acesso ao shell.

**Só o que o matcher do hook vê é inspecionado.** O que um processo já iniciado
faz depois está fora da cerca.

---

## Ainda não construído: camada de MCP de vídeo

Esta camada **não existe**. Está escrita aqui porque o risco já foi mapeado, e
porque um roadmap honesto vale mais do que descobrir a ausência em produção.

Servidores MCP de vídeo — geração, renderização, upload, publicação — não passam
pelo `PreToolUse` da forma que este guarda entende hoje. O guarda classifica
comando de shell e caminho de arquivo. Uma chamada MCP é um nome de ferramenta com
argumentos estruturados, e os perigos moram nos argumentos, não numa string de
comando.

Perigos já identificados, sem cobertura:

- **Publicação irreversível.** Subir vídeo para um canal ou perfil é ação
  externa, e o corpus já tem um incidente sobre publicar na conta errada
  (`published-under-the-wrong-identity`). A mesma classe de erro em vídeo é mais
  cara: o arquivo é grande, o processo é lento, e apagar depois não desfaz o que
  já foi distribuído.
- **Sobrescrita de renderização.** Render de vídeo custa minutos ou horas. Uma
  escrita no caminho de saída de um render anterior destrói trabalho que não tem
  backup porque ninguém versiona arquivo de 2 GB.
- **Teto de tamanho tratado como sucesso.** Upload que falha por limite de
  tamanho tende a devolver erro parcial, e o corpus já registra a classe geral em
  `truncated-output-treated-as-complete`: saída cortada tratada como completa.
- **Custo por chamada.** Geração de vídeo é a chamada mais cara de um fluxo
  típico. Repetição por retry automático é prejuízo direto, não latência.

O que falta para construir: classificação sobre argumentos estruturados de
ferramenta, em vez de sobre string de comando. Enquanto isso não existir, trate
qualquer fluxo de vídeo como fora da cerca e mantenha aprovação humana na
publicação.
