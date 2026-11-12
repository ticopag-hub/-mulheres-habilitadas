# Mulheres Habilitadas — Cloudflare Pages + D1 + R2

Projeto inicial sem dependência do Netlify ou Firebase. Interface em `public/`, API em Pages Functions, banco D1 e anexos no R2.

## 1. Pré-requisitos
- Conta Cloudflare.
- Node.js LTS e npm instalados em um computador.
- Wrangler: `npm install -g wrangler`.
- Faça login: `npx wrangler login`.

## 2. Criar banco e bucket
```bash
npx wrangler d1 create mulheres-habilitadas-db
npx wrangler r2 bucket create mulheres-habilitadas-arquivos
```
Copie o `database_id` retornado pelo primeiro comando para `wrangler.toml`, substituindo `PREENCHER_COM_O_ID_DO_D1`.

Crie as tabelas:
```bash
npx wrangler d1 execute mulheres-habilitadas-db --remote --file=./schema.sql
```

## 3. Segredos obrigatórios
Gere duas chaves fortes e diferentes (não use exemplos nem senhas de teste):
```bash
openssl rand -base64 32
```
Configure:
```bash
npx wrangler pages secret put SESSION_SECRET --project-name mulheres-habilitadas
npx wrangler pages secret put SETUP_KEY --project-name mulheres-habilitadas
```
Cole valores fortes e exclusivos quando o terminal solicitar. Guarde a `SETUP_KEY`: ela será usada uma única vez para criar o primeiro administrador. Nunca a coloque no HTML, GitHub ou em mensagens públicas.

## 4. Publicar
```bash
npx wrangler pages project create mulheres-habilitadas
npx wrangler pages deploy public --project-name mulheres-habilitadas
```
No painel Cloudflare Pages > projeto > Settings > Functions > Bindings, confirme:
- D1 database binding: variável `DB`, banco `mulheres-habilitadas-db`.
- R2 bucket binding: variável `FILES`, bucket `mulheres-habilitadas-arquivos`.
- Secrets `SESSION_SECRET` e `SETUP_KEY`.

As bindings também podem ser definidas por `wrangler.toml`; revise a configuração do projeto depois da primeira publicação. Em deploy via Git, configure o build output directory como `public` e mantenha a configuração do Wrangler.

## 5. Criar primeiro administrador
Depois de publicar e configurar as bindings, abra o console do navegador na página do site e execute uma requisição POST para `/api/setup` com JSON contendo `setupKey`, `name`, `username` e `password` (mínimo 10 caracteres). Exemplo via terminal:
```bash
curl -X POST https://SEU-PROJETO.pages.dev/api/setup \
 -H "Content-Type: application/json" \
 -d '{"setupKey":"SUA_SETUP_KEY","name":"Nome do administrador","username":"admin","password":"SENHA_FORTE_COM_10_CARACTERES"}'
```
Após sucesso, o endpoint de configuração inicial fica bloqueado porque já existe administrador. Crie os demais usuários dentro do painel.

## Funcionalidades incluídas
- Login individual com hash PBKDF2 (210 mil iterações), sessão em cookie HttpOnly, Secure e SameSite.
- Perfis administrador, supervisor e instrutor.
- Cadastro de veículos e usuários.
- Vistorias com quilometragem e itens de inspeção.
- Ocorrências com até 5 anexos de até 10 MB cada.
- Histórico filtrável por tipo, veículo e datas.
- Relatório mensal e exportação CSV.

## Notas importantes
- O projeto não migra os dados antigos; começa com banco vazio, conforme solicitado.
- Não existe hospedagem ou banco com uso literalmente ilimitado. D1, R2 e Pages têm cotas e políticas próprias; acompanhe o uso no painel Cloudflare.
- Faça backups periódicos do D1 e dos arquivos R2.
- A criação inicial do administrador é feita por endpoint protegido por segredo, não existe usuário/senha padrão.
- Para uso real com dados pessoais, recomenda-se revisão de segurança, política de privacidade, backups e teste antes de inserir dados operacionais.
