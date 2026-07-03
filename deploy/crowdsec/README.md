# Config do CrowdSec (IDS) — cópias versionadas

O `deploy.sh` **não** gerencia a configuração do CrowdSec; ela vive em `/etc/crowdsec`
no LXC de produção. Este diretório guarda cópias versionadas para reprodutibilidade.

## Como os bans funcionam (contexto)

- **Duração:** `profiles.yaml` aplica `duration: 87600h` (~10 anos = permanente) para
  toda remediação de escopo `Ip`/`Range` (`Alert.Remediation == true`). Não precisa
  configurar duração por cenário — qualquer cenário com `labels.remediation: true`
  vira ban permanente.
- **Enforcement:** `cs-firewall-bouncer` (dropa os pacotes no firewall). Há uma janela
  de ~1–2s entre a detecção e o drop, então o scanner pode fazer algumas requisições
  antes de ser bloqueado (todas já recebendo 444 do nginx `000-default-drop`).
- **Whitelists (antes do ban):** parser `mywhitelist.yaml` (rede própria), allowlist
  `painel` (gerida pelo painel via `cscli allowlists`) e a collection
  `crowdsecurity/whitelist-good-actors` (bots legítimos).

## Arquivos

- `sensitive-files-ban.yaml` — **cenário custom (novo).** Bane na 1ª tentativa de
  acesso a arquivo/pasta sensível (`.env`, `.git/`, `.aws/`, `.ssh/` + lista mantida
  `sensitive_data.txt`), em qualquer log/domínio. Complementa o `direct-ip-access`
  (que só cobre acesso pelo IP cru) e pré-empta o `http-sensitive-files` do hub
  (leaky, `capacity: 4` → só bane após 4 arquivos distintos).
- `reference-direct-ip-ban.yaml` — cópia de referência do cenário que bane acesso
  direto pelo IP (já existente em prod).
- `reference-profiles.yaml` — cópia de referência do `profiles.yaml` (duração dos bans).

## Instalar / atualizar o cenário custom em produção

```sh
# copia o cenário para o LXC
scp deploy/crowdsec/sensitive-files-ban.yaml root@SEU_SERVIDOR:/etc/crowdsec/scenarios/

# testa a config, recarrega e confirma
ssh root@SEU_SERVIDOR 'crowdsec -t && systemctl reload crowdsec && cscli scenarios list | grep sensitive-files-ban'
```

## Validar (sem falso-positivo)

```sh
# deve disparar (🟢 custom/http-sensitive-files-ban):
cscli explain --log '1.2.3.4 - - [.../...] "GET /.env HTTP/1.1" 404 100 "-" "curl/8"' --type nginx
cscli explain --log '5.6.7.8 - - [.../...] "GET /.git/config HTTP/1.1" 404 100 "-" "x"' --type nginx
# NÃO deve disparar (rota legítima):
cscli explain --log '9.9.9.9 - - [.../...] "GET /api/login HTTP/1.1" 200 88 "-" "x"' --type nginx
```
