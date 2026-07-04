# Contribuindo com o Mini SOC

Obrigado pelo interesse em contribuir! 🎉 Este projeto é open source sob a licença
[MIT](LICENSE) e contribuições são muito bem-vindas — desde correções de bug e
melhorias na documentação até novas funcionalidades.

Este guia explica como participar de forma que facilite a revisão e a manutenção.

## Índice

- [Código de conduta](#código-de-conduta)
- [Como posso ajudar?](#como-posso-ajudar)
- [Reportando bugs](#reportando-bugs)
- [Sugerindo melhorias](#sugerindo-melhorias)
- [Preparando o ambiente](#preparando-o-ambiente)
- [Fluxo de contribuição (Pull Requests)](#fluxo-de-contribuição-pull-requests)
- [Padrão de commits](#padrão-de-commits)
- [Estilo de código](#estilo-de-código)
- [Segurança](#segurança)

## Código de conduta

Seja respeitoso e construtivo. Trate todos com cordialidade, presuma boa-fé e
mantenha as discussões técnicas focadas no problema, não nas pessoas. Assédio,
discriminação ou comportamento hostil não serão tolerados.

## Como posso ajudar?

- 🐛 **Reportando bugs** que você encontrar.
- 💡 **Sugerindo melhorias** ou novas funcionalidades.
- 📖 **Melhorando a documentação** (README, comentários, este guia).
- 🔧 **Enviando código** — correções, testes ou features.

Se você é novo no projeto, procure issues marcadas como `good first issue`.

## Reportando bugs

Antes de abrir uma issue, verifique se ela **já não existe**. Ao abrir um bug,
inclua:

- **O que aconteceu** e **o que você esperava** que acontecesse.
- **Passos para reproduzir** (o mais objetivo possível).
- **Ambiente:** versão do Python, SO (ex.: Debian 12), versão do CrowdSec/nginx.
- **Logs relevantes** — mas **remova qualquer dado sensível** (IPs reais que você
  não queira expor, tokens, senhas, hashes) antes de colar.

## Sugerindo melhorias

Abra uma issue descrevendo:

- O **problema** que a melhoria resolve (o "porquê").
- A **proposta** de solução, se você já tiver uma ideia.
- Alternativas que considerou.

Para mudanças grandes, **abra uma issue de discussão antes** de investir tempo
codando — assim alinhamos a abordagem e evitamos retrabalho.

## Preparando o ambiente

O projeto é uma aplicação Python (FastAPI) que serve uma SPA. Requisitos e
instruções detalhadas estão no [README](README.md#início-rápido-devlocal).
Resumidamente:

```bash
# 1. Clone o seu fork
git clone git@github.com:SEU-USUARIO/Mini-SOC.git
cd Mini-SOC

# 2. Crie e ative um ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure o ambiente
cp .env.example .env
# edite o .env (gere um APP_SECRET forte — veja o README)

# 5. Rode em modo dev
uvicorn app:app --reload
```

> **Nunca** commite o seu `.env`, o banco `app.db` ou a pasta `.venv/` — eles já
> estão no [`.gitignore`](.gitignore).

## Fluxo de contribuição (Pull Requests)

1. **Faça um fork** do repositório e clone o seu fork.
2. **Crie um branch** a partir do `main` com um nome descritivo:
   ```bash
   git checkout -b fix/parse-log-malformado
   # ou feat/exportar-decisoes-csv
   ```
3. **Faça as mudanças** em commits pequenos e focados.
4. **Teste localmente** — garanta que o app sobe e que a funcionalidade afetada
   funciona.
5. **Abra o Pull Request** contra o branch `main`, descrevendo:
   - **o quê** mudou e **por quê**;
   - como testar / reproduzir;
   - screenshots, se houver mudança visual na UI.
6. Responda aos comentários da revisão. PRs pequenos e bem descritos são revisados
   mais rápido. 🙂

## Padrão de commits

Este projeto segue o formato [Conventional Commits](https://www.conventionalcommits.org/pt-br/).
Cada commit começa com um **tipo**, seguido de um escopo opcional e uma descrição
curta no imperativo:

```
<tipo>(<escopo opcional>): <descrição curta>
```

Tipos usados:

| Tipo       | Quando usar                                              |
| ---------- | ------------------------------------------------------- |
| `feat`     | nova funcionalidade                                     |
| `fix`      | correção de bug                                         |
| `docs`     | apenas documentação                                     |
| `refactor` | mudança de código sem alterar comportamento             |
| `chore`    | tarefas de manutenção (deps, config, `.gitignore`, etc) |
| `style`    | formatação, sem mudança de lógica                       |
| `test`     | adição ou ajuste de testes                              |

Exemplos reais do histórico do projeto:

```
feat(geoip): geolocalização no modal de detalhe do log
fix(logs): parseia requests malformadas do nginx (scans/lixo binário)
docs: README completo p/ novos usuários
```

## Estilo de código

- **Python:** siga a [PEP 8](https://peps.python.org/pep-0008/). Nomes claros,
  funções pequenas, e mantenha o estilo do código ao redor.
- **Coerência acima de tudo:** ao mexer num arquivo, imite as convenções que já
  existem nele (nomes, comentários, organização).
- **Comentários** em português, como o restante do projeto.
- Evite introduzir dependências novas sem necessidade — discuta antes em uma issue.

## Segurança

Se você encontrar uma **vulnerabilidade de segurança**, por favor **não abra uma
issue pública**. Reporte de forma privada ao mantenedor (pelo perfil do GitHub)
para que a falha possa ser corrigida antes de ser divulgada.

Lembre-se: esta é uma ferramenta de segurança que lida com IPs, logs e ações de
banimento. Tenha cuidado redobrado com qualquer código que toque em
autenticação, permissões ou execução de comandos (`cscli`).

---

Obrigado por contribuir com o Mini SOC! 💙
