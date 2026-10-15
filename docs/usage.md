# Guia de Operação e Uso — HS_WSS

Este guia orienta o operador no deployment, configuração, execução e procedimentos de auditoria utilizando o **HS_WSS (HS Tech Web Secret Scanner)**.

> **Nota de Sanitização:** Todos os endereços IP, portas e domínios mencionados neste documento utilizam faixas RFC 1918 e nomes fictícios de exemplo (ex: `192.168.0.10`, `192.168.0.50` e `https://app.example.local`).

---

## 1. Pré-requisitos

* Sistema operacional Linux (Ubuntu 22.04 LTS ou superior recomendado).
* Docker Engine (24.0+) e Docker Compose (v2.20+) instalados.
* Acesso ao diretório da aplicação: `/opt/hs_wss`.
* Porta TCP configurada e acessível na rede local (padrão: `8659`).

---

## 2. Configuração de Variáveis de Ambiente

1. Acesse o diretório do projeto:
   ```bash
   cd /opt/hs_wss
   ```

2. Caso esteja inicializando pela primeira vez, crie o arquivo `.env` a partir do modelo de exemplo:
   ```bash
   cp .env.example .env
   ```

3. Revise e ajuste os parâmetros do `.env` conforme a necessidade da sua auditoria:
   ```env
   # Endereço de escuta do servidor web e porta de acesso
   HOST=0.0.0.0
   PORT=8659

   # Persistência do banco SQLite
   DB_PATH=/opt/hs_wss/data/scanner.db

   # Limpeza automática de dados anteriores a cada nova inicialização (padrão: true)
   PURGE_ON_STARTUP=true

   # Limites de profundidade e quantidade máxima de páginas para o crawler
   MAX_CRAWL_DEPTH=3
   MAX_CRAWL_PAGES=50
   PAGE_TIMEOUT_MS=20000
   HEADLESS=true

   # Controles de segurança de rede
   BLOCK_METADATA_IPS=true
   ALLOWED_SCHEMES=http,https
   ```

---

## 3. Inicialização Efêmera (Modo Padrão via Docker)

O HS_WSS foi arquitetado para operar em **modo efêmero atrelado ao terminal**. Isso significa que a interface web só fica aberta e acessível enquanto o operador mantiver o processo rodando no terminal.

Para iniciar, execute no diretório `/opt/hs_wss`:

```bash
docker compose up --build
```

> **Aviso Importante:** **NÃO** utilize a flag `-d` (daemon mode). O contêiner deve permanecer em primeiro plano para garantir o ciclo de vida efêmero e o encerramento seguro com `Ctrl+C`.

Após o build e a inicialização, o terminal exibirá:

```text
================================================================================
  _    _  _____ __          __ _____  _____ 
 | |  | |/ ____|\ \        / // ____|/ ____|
 | |__| | (___   \ \  /\  / /| (___ | (___  
 |  __  |\___ \   \ \/  \/ /  \___ \ \___ \ 
 | |  | |____) |   \  /\  /   ____) |____) |
 |_|  |_|_____/     \/  \/   |_____/|_____/ 
                                            
 HS Tech Web Secret Scanner & Dynamic Interceptor
================================================================================
 [*] Modo de Execução: Efêmero atrelado ao terminal (Terminal-bound)
 [*] Binding Host:     0.0.0.0
 [*] Porta do Painel:  8659
 [*] Persistência:     /opt/hs_wss/data/scanner.db
 [*] Engine:           Playwright Headless + Regex Scanner
--------------------------------------------------------------------------------
 [>>>] Painel Web acessível em: http://0.0.0.0:8659
       (Na rede local, acesse via: http://<IP-DO-SERVIDOR>:8659)
 [!]   Pressione Ctrl+C para encerrar o scanner e desativar o painel web.
================================================================================
```

---

## 4. Operação do Painel Web (Estrutura de 3 Guias)

Abra o navegador no endereço do servidor (ex: `http://192.168.0.10:8659`). O painel é composto por 3 guias intuitivas:

### 4.1 Guia 1: Varredura (Configuração & Disparo)
1. **URL Alvo:** Insira o endereço completo da aplicação a ser auditada (ex: `http://192.168.0.50:8080` ou `https://app.example.local`).
2. **Profundidade:** Define quantos níveis de links internos o crawler deve seguir a partir da rota inicial (padrão: 3 níveis).
3. **Limite de Páginas:** Quantidade máxima de páginas a visitar na mesma execução (padrão: 50 páginas).
4. **Autenticação Opcional no Alvo:**
   - Se a aplicação exigir autenticação prévia para liberar rotas protegidas, marque o checkbox **"A aplicação requer autenticação prévia?"**.
   - Preencha o **Usuário / E-mail** e a **Senha**.
   - *(Opcional)* Preencha a **URL de Login**, caso seja uma rota específica diferente da página inicial.
   - **Garantia de Privacidade:** As credenciais existem estritamente na memória volátil (RAM) durante a tentativa de login e são destruídas imediatamente após o processo, nunca sendo persistidas em banco de dados ou logs.
5. Clique em **Iniciar Varredura**. O sistema iniciará a auditoria e alternará automaticamente para a guia **Status da varredura**.

---

### 4.2 Guia 2: Status da varredura (Monitoramento em Tempo Real)
* **Acompanhamento ao Vivo:**
  - **Status:** Badge indicativo (`Executando`, `Concluído`, `Interrompido`).
  - **Alerta de Autenticação:**
    - Se as credenciais forem aceitas pelo site, um banner verde confirma a sessão autenticada.
    - Se o login for recusado ou os campos não forem encontrados, um banner vermelho alerta imediatamente: `⚠️ Atenção: A autenticação com usuário e senha falhou no site.` com o motivo detectado.
  - **Rota Atual:** Exibe a URL sendo analisada no instante exato.
  - **Métricas (KPIs):** Contadores dinâmicos de páginas analisadas, segredos críticos, segredos altos e total de ocorrências.
* **Tabela de Descobertas:**
  - Atualizada instantaneamente via Server-Sent Events (SSE).
  - Exibe Severidade, Tipo de Segredo, Valor Mascarado, Localização e Origem (`DOM`, `SCRIPT`, `XHR_RESPONSE`).
  - **Botão `👁️ Revelar` / `🔒 Ocultar`:** Permite visualizar temporariamente o segredo completo exclusivamente na tela do operador para validação rápida, sem persistência no backend.
  - **Botão `🔍 Detalhes`:** Abre o modal exibindo o trecho sanitizado de código onde a chave foi detectada.
* **Ações Operacionais:**
  - **Interromper:** Cancela a varredura a qualquer momento com segurança.
  - **Exportar JSON / CSV:** Faz download imediato do relatório da varredura atual.

---

### 4.3 Guia 3: Histórico (Auditorias Anteriores & Detalhamento Inline)
* **Registro de Auditorias:** Lista todas as execuções salvas no SQLite, contendo ID, Domínio, Status, Total de Páginas, Quantidade de Segredos e Data/Hora.
* **Identificação de Login:** Exibe a tag `⚠️ Login Falhou` ou `🔐 Autenticado` na coluna da aplicação para varreduras que utilizaram credenciais.
* **Visualização Inline:** Ao clicar no botão **`👁️ Visualizar`**, abre uma seção de detalhes logo abaixo da tabela selecionada, contendo:
  - O resumo das métricas daquela análise.
  - Status e alerta detalhado de autenticação daquela execução.
  - A tabela completa de todos os segredos encontrados na respectiva análise, com suporte a revelação de segredo e inspeção de snippets.
  - Botões para exportação do histórico específico em formato JSON ou CSV.
* **Limpeza do Histórico:** O botão **`🧹 Limpar Histórico`** no cabeçalho permite purgar todas as varreduras anteriores sob demanda.

---

## 5. Encerramento da Sessão

Ao concluir a auditoria:

1. Volte à janela do terminal onde o contêiner está rodando.
2. Pressione as teclas `Ctrl+C`.
3. O contêiner intercepta o sinal `SIGINT`, cancela graciosamente eventuais tarefas ativas do Playwright e encerra o Uvicorn.
4. O painel web fica imediatamente inacessível, garantindo que o servidor permaneça fechado e seguro.
5. Os dados registrados permanecem preservados em `/opt/hs_wss/data/scanner.db`.

---

## 6. Execução Standalone (Ambiente Python sem Docker)

Caso prefira executar o HS_WSS diretamente na máquina local sem utilizar contêineres:

1. Crie e ative um ambiente virtual Python:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Instale as dependências e baixe o binário do Chromium para o Playwright:
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

3. Inicie o servidor:
   ```bash
   python3 -m app.main
   ```

4. Acesse em `http://127.0.0.1:8659`. Para finalizar, pressione `Ctrl+C`.

---

## 7. Solução de Problemas Comuns (Troubleshooting)

### 7.1 Porta 8659 já em uso
Se a porta padrão estiver ocupada por outro serviço no servidor:
- Edite o arquivo `/opt/hs_wss/.env` e altere para outra porta livre (ex: `PORT=8670`).
- Reinicie o contêiner com `docker compose up --build`.

### 7.2 Erro de SSRF ao iniciar varredura
Se a mensagem *"Target URL is not allowed due to security / SSRF protection rules"* for exibida:
- O HS_WSS bloqueia requisições para endereços de metadados de nuvem (`169.254.169.254`, etc.) e esquemas não-HTTP.
- Verifique se a URL alvo inicia corretamente com `http://` ou `https://`.

### 7.3 Falha de login indicada no painel
Se o painel exibir `⚠️ Atenção: A autenticação com usuário e senha falhou no site`:
- Verifique se a aplicação alvo possui campos padrão de login (`user`, `login`, `email`, `password`).
- Verifique se a URL de login necessita ser informada manualmente no campo opcional **URL de Login** (ex: `http://192.168.0.50:8080/auth/login`).
