# Catálogo e Customização de Regras Regex — HS_WSS

O **HS_WSS** utiliza um motor de análise estática e dinâmica baseado em Expressões Regulares (Regex) de alta fidelidade combinado com verificação heurística de **Entropia de Shannon** para identificar credenciais vazadas e minimizar falsos positivos.

> **Diretriz de Segurança e Não-Emissão de Credenciais:**  
> Para garantir absoluta conformidade em repositórios públicos e evitar qualquer risco de geração acidental de valores coincidentes ou alarmes falsos em scanners de segredos (ex: GitHub Secret Scanning, Gitleaks), **este documento não contém strings geradas ou exemplos de tokens reais/simulados**. Todas as regras são representadas exclusivamente pela sua especificação técnica, expressões regulares e modelos de estrutura sintática `<PLACEHOLDER>`.

---

## 1. Regras Nativas Incluídas

| ID da Regra | Nome do Padrão | Severidade | Descrição do Padrão | Formato Sintático / Estrutura Esperada |
| :--- | :--- | :--- | :--- | :--- |
| `aws-access-key-id` | AWS Access Key ID | **CRITICAL** | Identificador de 20 caracteres iniciado pelo prefixo de conta AWS (`AKIA`, `ABIA`, `ACCA`, `ASIA`) seguido de 16 caracteres alfanuméricos em caixa alta. | `<PREFIXO_20_CHARS_AKIA_ABIA_ACCA_ASIA>` |
| `aws-secret-access-key` | AWS Secret Access Key | **CRITICAL** | Chave secreta de 40 caracteres associada a uma conta AWS, identificada por atribuição explícita (`aws_secret_access_key`, `secret_key`). | `aws_secret_access_key='<CHAVE_SECRETA_40_CARACTERES>'` |
| `github-token` | GitHub Personal Token | **CRITICAL** | Token de acesso pessoal clássico ou Fine-Grained do ecossistema GitHub (`ghp_`, `gho_`, `github_pat_`). | `ghp_<TOKEN_ALFANUMERICO_36_CARACTERES>` |
| `google-api-key` | Google Cloud / Firebase API Key | **HIGH** | Chave de API de 39 caracteres da GCP/Firebase iniciada pelo prefixo `AIza`. | `AIza<CHAVE_API_GCP_35_CARACTERES>` |
| `slack-token` | Slack API Token | **HIGH** | Token de integração ou bot da API do Slack iniciado pelos identificadores `xoxb-`, `xoxp-`, etc. | `xoxb-<ID_EQUIPE>-<ID_USUARIO>-<TOKEN_ALFANUMERICO>` |
| `slack-webhook` | Slack Incoming Webhook | **HIGH** | URL de webhook de entrada para disparo de mensagens em canais Slack. | `https://hooks.slack.com/services/<WORKSPACE_ID>/<CANAL_ID>/<TOKEN>` |
| `stripe-api-key` | Stripe Live Secret Key | **CRITICAL** | Chave de API de produção da Stripe iniciada pelos prefixos `sk_live_` ou `rk_live_`. | `sk_live_<IDENTIFICADOR_STRIPE_24_OU_MAIS_CHARS>` |
| `private-key` | Chave Criptográfica Privada | **CRITICAL** | Cabeçalho e rodapé delimitadores de bloco PEM de chave privada (RSA, EC, DSA, OPENSSH). | `-----BEGIN [TIPO] PRIVATE KEY----- ... -----END [TIPO] PRIVATE KEY-----` |
| `database-uri` | Connection String com Senha | **CRITICAL** | URI de conexão para Postgres, MySQL, MongoDB ou Redis contendo usuário e senha em texto claro. | `<DRIVER>://<USUARIO>:<SENHA>@<HOST>:<PORTA>/<DATABASE>` |
| `generic-api-key` | Chave Genérica de Alta Entropia | **HIGH** | Atribuição de tokens de 20 a 80 caracteres em variáveis sensíveis (`api_key`, `secret_key`, `token`). | `<NOME_VARIAVEL> = "<STRING_ALTA_ENTROPIA_20_A_80_CHARS>"` |
| `jwt-token` | JSON Web Token (JWT) | **MEDIUM** | Token assinado composto por três segmentos codificados em Base64URL separados por ponto. | `<HEADER_BASE64>.<PAYLOAD_BASE64>.<ASSINATURA_BASE64>` |

---

## 2. Superfícies Auditadas pelo Motor

Durante a navegação com o Playwright, as regras são avaliadas concorrentemente em 4 superfícies da aplicação alvo:

1. **DOM Renderizado:** Todo o HTML gerado após a execução dos scripts do framework frontend (comentários HTML, atributos `data-*`, campos de formulário ocultos).
2. **Scripts JavaScript:** Arquivos `.js` e blocos de scripts inline carregados em tempo de execução.
3. **Respostas de Rede (XHR / Fetch):** Payloads JSON, XML e textuais retornados por chamadas de API disparadas pela página.
4. **Cabeçalhos de Requisição:** Headers de autorização (`Authorization: Bearer`, `X-Api-Key`, `Cookie`) transmitidos pelo cliente.

---

## 3. Filtros Anti-Falso Positivo & Entropia de Shannon

Para evitar que identificadores comuns de código (como hashes CSS de compilação Webpack/Vite ou strings estáticas de teste) poluam os resultados, o HS_WSS aplica dois filtros:

1. **Lista de Exclusão de Termos Triviais:** Strings comuns como `undefined`, `null`, `false`, `localhost`, `placeholder`, `application/json` e sequências de repetição contínua são automaticamente descartadas.
2. **Entropia de Shannon Mínima:** Regras genéricas calculam a entropia da cadeia através da fórmula estatística:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Cadeias com entropia inferior ao limiar exigido (ex: $H < 3.5$) são rejeitadas por falta de aleatoriedade criptográfica, diferenciando identificadores previsíveis de tokens reais.

---

## 4. Mascaramento Seguro e Extração de Trechos (Snippets)

Quando uma ocorrência é detectada pelo motor:
- **Mascaramento Protetor:** O valor é mascarado de forma padronizada preservando apenas os 4 primeiros e 4 últimos caracteres (ex: `[PREFIXO_4_CHARS]****************[SUFIXO_4_CHARS]`). Isso permite que o analista reconheça a origem do token sem expor o conteúdo sensível da credencial.
- **Higienização de Contexto:** O trecho de código ao redor do segredo (context snippet de ±120 caracteres) tem a chave real imediatamente substituída pelo valor mascarado antes de ser transmitido à interface ou persistido.
- **Revelação sob Demanda:** Caso o operador decida inspecionar a chave completa para validação, o botão `👁️ Revelar` exibe o valor estritamente no elemento visual da tela local, sem nenhuma gravação em disco.

---

## 5. Como Adicionar Regras Personalizadas

O sistema permite carregar padrões customizados sem alterar o código-fonte da aplicação.

1. Crie ou edite o arquivo no caminho configurado na variável `CUSTOM_REGEX_FILE` (padrão: `/opt/hs_wss/data/custom_rules.json`):

   ```json
   {
     "rules": [
       {
         "id": "internal-corp-token",
         "name": "Token Interno Corporativo",
         "pattern": "\\b(CORP_[A-Za-z0-9]{32})\\b",
         "severity": "CRITICAL",
         "description": "Token de acesso do barramento corporativo de microsserviços.",
         "capture_group": 1,
         "min_length": 37
       },
       {
         "id": "custom-storage-token",
         "name": "Token Customizado de Armazenamento",
         "pattern": "(?i)storage_secret\\s*[:=]\\s*['\"]([A-Za-z0-9_-]{30,60})['\"]",
         "severity": "HIGH",
         "description": "Chave de acesso a bucket de armazenamento interno.",
         "capture_group": 1,
         "entropy_threshold": 3.6,
         "min_length": 30
       }
     ]
   }
   ```

2. O arquivo é lido automaticamente na inicialização da aplicação, combinando as novas regras às regras nativas do sistema.
