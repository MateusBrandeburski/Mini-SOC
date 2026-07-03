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
- `crowdsec-nginx-bouncer.conf.example` — **config de referência do bouncer L7**
  (sem a API key). Ver seção abaixo.
- `direct-ip-ban.yaml` — cenário que bane **na hora** quem acessa pelo IP cru /
  host inválido (linhas do `000-default-drop`, `direct_ip=true`). **Exceção:**
  `robots.txt` e `favicon.ico` sozinhos NÃO banem (crawlers/monitores legítimos
  tocam o IP; scanner real sonda outros paths e cai no ban no primeiro deles).
  Instala em `/etc/crowdsec/scenarios/direct-ip-ban.yaml` (`crowdsec -t && systemctl reload crowdsec`).
- `waf-ban.html` — **tela de bloqueio (403) customizada** servida pelo nginx-bouncer.
  Título "Bloqueado pelo WAF", contato do admin, data (via JS) + "MINI SOC — BOTS
  NÃO PASSARÃO!", sem marca do CrowdSec. Instala em
  `/var/lib/crowdsec/lua/templates/ban.html` + `nginx -t && systemctl reload nginx`.
- `reference-profiles.yaml` — cópia de referência do `profiles.yaml` (duração dos bans).

## Cenários desativados (menos falso-positivo em uso normal)

Cenários **comportamentais** que banavam usuário legítimo (ex.: SPA que dispara
POSTs de login retornando 401, muitos requests dinâmicos, alguns 404) foram
**desativados** — bans graves são feitos na mão. Desativados via
`cscli scenarios remove <nome> --force` + `systemctl reload crowdsec`:

- `crowdsecurity/http-generic-bf` — **atenção:** este arquivo do hub
  (`hub/scenarios/crowdsecurity/http-generic-bf.yaml`) foi modificado e também
  define `LePresidente/http-generic-401-bf` e `LePresidente/http-generic-403-bf`
  (leaky, capacity 5 / 10s → 5 POST 401/403 em ~50s = ban). Remover o
  `http-generic-bf` desativa os **três**.
- `crowdsecurity/http-crawl-non_statics` — crawling de recursos não-estáticos.
- `crowdsecurity/http-probing` — probing genérico de 404.

**Mantidos ativos** (ataques reais): todos os CVE/exploits, `custom/sensitive-files-ban`,
`custom/direct-ip-access`, `http-sqli/xss/path-traversal/cve/admin-interface-probing`,
`http-backdoors-attempts`, `http-bad-user-agent`, w00tw00t, sshd + bans manuais.

Re-ativar (se quiser): `cscli scenarios install crowdsecurity/http-generic-bf` etc.
+ `systemctl reload crowdsec`.

## Bouncer no nginx (L7) — bloqueia banido que vem via Cloudflare

**Problema:** o `cs-firewall-bouncer` bloqueia na camada 3/4 pelo IP do pacote. No
tráfego via Cloudflare (domínio), o pacote chega com o IP da borda da CF, não o do
atacante — então o IP banido **passa**. Só é bloqueado no acesso direto pelo IP cru.

**Solução:** o `crowdsec-nginx-bouncer` roda dentro do nginx (lua) e checa o **IP real**
(`CF-Connecting-IP`, já resolvido pelo `real_ip` em `conf.d/cloudflare-realip.conf`)
contra as decisões do CrowdSec, devolvendo **403** para banidos. Convive com o
firewall-bouncer (que segue cobrindo acesso direto / não-HTTP).

### Instalar em produção

```sh
apt-get install -y crowdsec-nginx-bouncer      # puxa libnginx-mod-http-lua, luarocks
# registra a API key sozinho e instala /etc/nginx/conf.d/crowdsec_nginx.conf

# AJUSTE OBRIGATÓRIO: usar stream (o modo "live" padrão não bloqueou de forma
# confiável nos testes desta stack — nginx 1.26 + bouncer 1.1.6):
sed -i 's/^MODE=.*/MODE=stream/' /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf

nginx -t && systemctl reload nginx
cscli bouncers list      # deve listar o crowdsec-nginx-bouncer, Valid + Last API pull
```

### Verificar (bloqueio pelo IP real, isolado/reversível)

```sh
cscli decisions add --ip 203.0.113.99 -d 10m
# server temporário que confia no header do localhost e SERVE conteúdo
# (use content_by_lua/proxy/root — NÃO `return 200`, que pula a fase access):
cat >/etc/nginx/conf.d/zz-cstest.conf <<'C'
server { listen 127.0.0.1:8899; server_name _;
  set_real_ip_from 127.0.0.1; real_ip_header CF-Connecting-IP;
  location / { default_type text/plain; content_by_lua_block { ngx.say("ok") } } }
C
nginx -t && systemctl reload nginx && sleep 15   # stream precisa popular
curl -s -o /dev/null -w '%{http_code}\n' -H 'CF-Connecting-IP: 203.0.113.99' http://127.0.0.1:8899/  # 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'CF-Connecting-IP: 8.8.8.8'      http://127.0.0.1:8899/  # 200
# limpar:
rm /etc/nginx/conf.d/zz-cstest.conf; cscli decisions delete --ip 203.0.113.99; nginx -t && systemctl reload nginx
```

**Notas:**
- Propagação de um novo ban leva até `UPDATE_FREQUENCY` (10s) no modo stream.
- Só locations que chegam à fase *access* são protegidas (proxy_pass, root, content_by_lua).
  `return`/`if ... return 444` (fase rewrite) não passam pelo bouncer — o que é ok
  (o `000-default-drop` já devolve 444 para host inválido).
- O painel Mini SOC (`:8100`) roda fora do nginx → não é afetado.
- Rollback: `ENABLED=false` no conf + `nginx -t && systemctl reload nginx`.

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
