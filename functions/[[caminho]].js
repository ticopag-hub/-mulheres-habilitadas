
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers
    }
  });

const enc = new TextEncoder();
const uid = () => crypto.randomUUID();
const ROLES = ['admin', 'supervisor', 'instructor'];

const b64 = bytes =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

async function hashPass(pass, salt) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: enc.encode(salt),
    iterations: 210000,
    hash: 'SHA-256'
  }, key, 256);
  return b64(bits);
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  return b64(await crypto.subtle.sign('HMAC', key, enc.encode(value)));
}

function cookieVal(request, name) {
  return (request.headers.get('Cookie') || '')
    .split(';')
    .map(part => part.trim())
    .find(part => part.startsWith(name + '='))
    ?.slice(name.length + 1);
}

function sessionCookie(value, maxAge = 86400) {
  return `mh_session=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function getSessionUser(request, env) {
  const raw = cookieVal(request, 'mh_session');
  if (!raw || !env.SESSION_SECRET || !env.DB) return null;

  try {
    const [id, exp, signature] = raw.split('.');
    if (!id || !exp || !signature || !Number.isFinite(Number(exp)) || Number(exp) < Date.now()) {
      return null;
    }

    const expected = await sign(`${id}.${exp}`, env.SESSION_SECRET);
    if (expected !== signature) return null;

    return await env.DB.prepare(
      'SELECT id, name, username, role FROM users WHERE id = ? AND active = 1'
    ).bind(id).first();
  } catch {
    return null;
  }
}

async function readBody(request) {
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('application/json')) return {};
  try {
    return await request.json();
  } catch {
    throw new Error('O conteúdo enviado não é um JSON válido.');
  }
}

const cleanText = value => String(value ?? '').trim();
const isAllowed = (user, roles) => Boolean(user && roles.includes(user.role));

function dateBR(value) {
  if (!value) return '';
  return new Date(value).toLocaleString('pt-BR', {
    timeZone: 'America/Sao_Paulo'
  });
}

function errorMessage(error) {
  const message = error?.message || '';
  if (message.includes('UNIQUE constraint failed')) {
    return 'Esse usuário ou placa já está cadastrado.';
  }
  if (message.includes('FOREIGN KEY constraint failed')) {
    return 'Não foi possível concluir: existem registros relacionados.';
  }
  if (message.includes('no such table')) {
    return 'As tabelas do banco ainda não foram criadas. Confira a execução do schema.sql no D1.';
  }
  return message || 'Ocorreu um erro interno.';
}

function validMonth(month) {
  if (!/^\d{4}-\d{2}$/.test(month || '')) return false;
  const number = Number(month.slice(5, 7));
  return number >= 1 && number <= 12;
}

export async function onRequest({ request, env }) {
  try {
    if (!env.DB) {
      return json({ error: 'Vínculo D1 DB não encontrado na configuração da Cloudflare.' }, 500);
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
    const method = request.method.toUpperCase();

    // Verifica se ainda é necessário criar o primeiro administrador.
    if (path === 'setup-status' && method === 'GET') {
      const result = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1"
      ).first();
      return json({ setupRequired: Number(result?.n || 0) === 0 });
    }

    // Cria o primeiro administrador usando SETUP_KEY.
    if (path === 'setup' && method === 'POST') {
      const data = await readBody(request);
      if (!env.SETUP_KEY || data.setupKey !== env.SETUP_KEY) {
        return json({ error: 'Chave de configuração inválida.' }, 403);
      }

      const count = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1"
      ).first();
      if (Number(count?.n || 0) > 0) {
        return json({ error: 'A configuração inicial já foi concluída.' }, 409);
      }

      const name = cleanText(data.name);
      const username = cleanText(data.username).toLowerCase();
      const password = String(data.password || '');
      if (!name || !username || password.length < 10) {
        return json({ error: 'Informe nome, usuário e senha com pelo menos 10 caracteres.' }, 400);
      }

      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const passwordHash = await hashPass(password, salt);
      await env.DB.prepare(`
        INSERT INTO users (id, name, username, role, salt, password_hash, active, created_at)
        VALUES (?, ?, ?, 'admin', ?, ?, 1, ?)
      `).bind(uid(), name, username, salt, passwordHash, new Date().toISOString()).run();

      return json({ ok: true });
    }

    // Login.
    if (path === 'login' && method === 'POST') {
      const data = await readBody(request);
      const username = cleanText(data.username).toLowerCase();
      const password = String(data.password || '');
      const user = await env.DB.prepare(
        'SELECT id, username, salt, password_hash FROM users WHERE username = ? AND active = 1'
      ).bind(username).first();

      if (!user || await hashPass(password, user.salt) !== user.password_hash) {
        return json({ error: 'Usuário ou senha incorretos.' }, 401);
      }
      if (!env.SESSION_SECRET) {
        return json({ error: 'O segredo SESSION_SECRET não foi configurado na Cloudflare.' }, 500);
      }

      const expires = Date.now() + 86400000;
      const value = `${user.id}.${expires}`;
      const signature = await sign(value, env.SESSION_SECRET);
      return json({ ok: true }, 200, {
        'set-cookie': sessionCookie(`${value}.${signature}`)
      });
    }

    // Logout.
    if (path === 'logout' && method === 'POST') {
      return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
    }

    // Usuário da sessão atual.
    if (path === 'me' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return json({ error: 'Não autenticado.' }, 401);
      return json({
        user: {
          ...user,
          roleLabel: {
            admin: 'Administrador',
            supervisor: 'Professor Sênior',
            instructor: 'Professor'
          }[user.role]
        }
      });
    }

    // Todas as outras rotas exigem uma sessão válida.
    const user = await getSessionUser(request, env);
    if (!user) return json({ error: 'Não autenticado.' }, 401);

    const isAdmin = user.role === 'admin';
    const isManager = isAllowed(user, ['admin', 'supervisor']);

    // Painel principal.
    if (path === 'dashboard' && method === 'GET') {
      const [carsResult, checksResult, incidentsResult, recentResult] = await Promise.all([
        env.DB.prepare('SELECT * FROM cars WHERE active = 1 ORDER BY model').all(),
        env.DB.prepare('SELECT COUNT(*) AS n FROM checks').first(),
        env.DB.prepare('SELECT COUNT(*) AS n FROM incidents').first(),
        env.DB.prepare(`
          SELECT * FROM (
            SELECT 'Vistoria' AS kind, c.model || ' · ' || c.plate AS car,
              ck.created_at AS date, u.name AS author
            FROM checks ck JOIN cars c ON c.id = ck.car_id JOIN users u ON u.id = ck.user_id
            UNION ALL
            SELECT 'Ocorrência' AS kind, c.model || ' · ' || c.plate AS car,
              i.created_at AS date, u.name AS author
            FROM incidents i JOIN cars c ON c.id = i.car_id JOIN users u ON u.id = i.user_id
          ) ORDER BY date DESC LIMIT 8
        `).all()
      ]);

      return json({
        cars: carsResult.results || [],
        checks: Number(checksResult?.n || 0),
        incidents: Number(incidentsResult?.n || 0),
        recent: (recentResult.results || []).map(row => ({ ...row, date: dateBR(row.date) }))
      });
    }

    // Registrar vistoria: todos os perfis autenticados.
    if (path === 'checks' && method === 'POST') {
      const data = await readBody(request);
      const km = Number(data.km);
      if (!data.car_id || !Number.isFinite(km) || km < 0) {
        return json({ error: 'Veículo e quilometragem válidos são obrigatórios.' }, 400);
      }
      const car = await env.DB.prepare(
        'SELECT id FROM cars WHERE id = ? AND active = 1'
      ).bind(data.car_id).first();
      if (!car) return json({ error: 'Veículo não encontrado ou inativo.' }, 400);

      const createdAt = new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare(`
          INSERT INTO checks (id, car_id, user_id, km, tires, oil, fuel, clean, notes, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          uid(), data.car_id, user.id, km,
          data.tires ? 1 : 0, data.oil ? 1 : 0,
          data.fuel ? 1 : 0, data.clean ? 1 : 0,
          cleanText(data.notes), createdAt
        ),
        env.DB.prepare('UPDATE cars SET km = ? WHERE id = ?').bind(km, data.car_id)
      ]);
      return json({ ok: true });
    }

    // Registrar ocorrência: administrador e professor sênior.
    if (path === 'incidents' && method === 'POST') {
      if (!isManager) return json({ error: 'Sem permissão para registrar ocorrências.' }, 403);
      const data = await readBody(request);
      const description = cleanText(data.description);
      const severity = cleanText(data.severity);
      if (!data.car_id || !description || !severity) {
        return json({ error: 'Preencha veículo, gravidade e descrição.' }, 400);
      }
      const car = await env.DB.prepare(
        'SELECT id FROM cars WHERE id = ? AND active = 1'
      ).bind(data.car_id).first();
      if (!car) return json({ error: 'Veículo não encontrado ou inativo.' }, 400);

      await env.DB.prepare(`
        INSERT INTO incidents (id, car_id, user_id, severity, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(uid(), data.car_id, user.id, severity, description, new Date().toISOString()).run();
      return json({ ok: true });
    }

    // Histórico: todos os perfis podem consultar.
    if (path === 'history' && method === 'GET') {
      const type = url.searchParams.get('type') || 'all';
      const carId = url.searchParams.get('car') || '';
      const from = url.searchParams.get('from') || '';
      const to = url.searchParams.get('to') || '';
      if (!['all', 'check', 'incident'].includes(type)) {
        return json({ error: 'Tipo de histórico inválido.' }, 400);
      }
      const rows = [];

      if (type !== 'incident') {
        let query = `
          SELECT ck.id, 'Vistoria' AS kind, c.model || ' · ' || c.plate AS car,
            ck.created_at AS date, u.name AS author, ck.km AS km,
            COALESCE(ck.notes, '') AS summary
          FROM checks ck JOIN cars c ON c.id = ck.car_id JOIN users u ON u.id = ck.user_id
          WHERE 1 = 1
        `;
        const params = [];
        if (carId) { query += ' AND ck.car_id = ?'; params.push(carId); }
        if (from) { query += ' AND date(ck.created_at) >= date(?)'; params.push(from); }
        if (to) { query += ' AND date(ck.created_at) <= date(?)'; params.push(to); }
        const result = await env.DB.prepare(query).bind(...params).all();
        rows.push(...(result.results || []));
      }

      if (type !== 'check') {
        let query = `
          SELECT i.id, 'Ocorrência' AS kind, c.model || ' · ' || c.plate AS car,
            i.created_at AS date, u.name AS author, NULL AS km,
            i.severity || ': ' || i.description AS summary
          FROM incidents i JOIN cars c ON c.id = i.car_id JOIN users u ON u.id = i.user_id
          WHERE 1 = 1
        `;
        const params = [];
        if (carId) { query += ' AND i.car_id = ?'; params.push(carId); }
        if (from) { query += ' AND date(i.created_at) >= date(?)'; params.push(from); }
        if (to) { query += ' AND date(i.created_at) <= date(?)'; params.push(to); }
        const result = await env.DB.prepare(query).bind(...params).all();
        rows.push(...(result.results || []));
      }

      rows.sort((a, b) => String(b.date).localeCompare(String(a.date)));
      return json({ rows: rows.map(row => ({ ...row, date: dateBR(row.date) })) });
    }

    // Cadastro de veículo: administrador e professor sênior.
    if (path === 'cars' && method === 'POST') {
      if (!isManager) return json({ error: 'Sem permissão.' }, 403);
      const data = await readBody(request);
      const model = cleanText(data.model);
      const plate = cleanText(data.plate).toUpperCase();
      const km = Number(data.km);
      if (!model || !plate || !Number.isFinite(km) || km < 0) {
        return json({ error: 'Informe modelo, placa e quilometragem válida.' }, 400);
      }
      await env.DB.prepare(`
        INSERT INTO cars (id, model, plate, km, active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
      `).bind(uid(), model, plate, km, new Date().toISOString()).run();
      return json({ ok: true });
    }

    // Editar ou desativar veículo.
    const carMatch = path.match(/^cars\/([^/]+)$/);
    if (carMatch && ['PATCH', 'DELETE'].includes(method)) {
      if (!isManager) return json({ error: 'Sem permissão.' }, 403);
      const id = carMatch[1];
      const existing = await env.DB.prepare('SELECT id FROM cars WHERE id = ?').bind(id).first();
      if (!existing) return json({ error: 'Veículo não encontrado.' }, 404);

      if (method === 'DELETE') {
        await env.DB.prepare('UPDATE cars SET active = 0 WHERE id = ?').bind(id).run();
        return json({ ok: true });
      }

      const data = await readBody(request);
      const model = cleanText(data.model);
      const plate = cleanText(data.plate).toUpperCase();
      const km = Number(data.km);
      if (!model || !plate || !Number.isFinite(km) || km < 0) {
        return json({ error: 'Informe modelo, placa e quilometragem válida.' }, 400);
      }
      await env.DB.prepare(
        'UPDATE cars SET model = ?, plate = ?, km = ? WHERE id = ?'
      ).bind(model, plate, km, id).run();
      return json({ ok: true });
    }

    // Cadastro de usuário: administrador e professor sênior.
    if (path === 'users' && method === 'POST') {
      if (!isManager) return json({ error: 'Sem permissão.' }, 403);
      const data = await readBody(request);
      const name = cleanText(data.name);
      const username = cleanText(data.username).toLowerCase();
      const password = String(data.password || '');
      const role = cleanText(data.role);
      if (!name || !username || password.length < 10 || !ROLES.includes(role)) {
        return json({ error: 'Informe nome, usuário, perfil e senha com pelo menos 10 caracteres.' }, 400);
      }
      if (!isAdmin && role === 'admin') {
        return json({ error: 'Somente o Administrador pode criar outro Administrador.' }, 403);
      }
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const passwordHash = await hashPass(password, salt);
      await env.DB.prepare(`
        INSERT INTO users (id, name, username, role, salt, password_hash, active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
      `).bind(uid(), name, username, role, salt, passwordHash, new Date().toISOString()).run();
      return json({ ok: true });
    }

    // Editar ou desativar usuário.
    const userMatch = path.match(/^users\/([^/]+)$/);
    if (userMatch && ['PATCH', 'DELETE'].includes(method)) {
      if (!isManager) return json({ error: 'Sem permissão.' }, 403);
      const id = userMatch[1];
      const target = await env.DB.prepare(
        'SELECT id, name, username, role, active FROM users WHERE id = ?'
      ).bind(id).first();
      if (!target) return json({ error: 'Usuário não encontrado.' }, 404);
      if (!isAdmin && target.role === 'admin') {
        return json({ error: 'Somente o Administrador pode alterar uma conta de Administrador.' }, 403);
      }

      if (method === 'DELETE') {
        if (id === user.id) {
          return json({ error: 'Você não pode excluir seu próprio usuário enquanto estiver conectado.' }, 400);
        }
        if (target.role === 'admin') {
          const admins = await env.DB.prepare(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1"
          ).first();
          if (Number(admins?.n || 0) <= 1) {
            return json({ error: 'Não é possível desativar o último Administrador.' }, 400);
          }
        }
        await env.DB.prepare('UPDATE users SET active = 0 WHERE id = ?').bind(id).run();
        return json({ ok: true });
      }

      const data = await readBody(request);
      const name = cleanText(data.name);
      const username = cleanText(data.username).toLowerCase();
      const role = cleanText(data.role);
      if (!name || !username || !ROLES.includes(role)) {
        return json({ error: 'Informe nome, usuário e perfil válidos.' }, 400);
      }
      if (!isAdmin && role === 'admin') {
        return json({ error: 'Somente o Administrador pode definir o perfil Administrador.' }, 403);
      }
      if (target.role === 'admin' && role !== 'admin') {
        const otherAdmins = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1 AND id <> ?"
        ).bind(id).first();
        if (Number(otherAdmins?.n || 0) === 0) {
          return json({ error: 'Não é possível retirar o perfil do último Administrador ativo.' }, 400);
        }
      }
      if (id === user.id && role !== user.role) {
        return json({ error: 'Não é possível alterar o próprio perfil.' }, 400);
      }
      await env.DB.prepare(
        'UPDATE users SET name = ?, username = ?, role = ? WHERE id = ?'
      ).bind(name, username, role, id).run();
      return json({ ok: true });
    }

    // Redefinir senha.
    const passwordMatch = path.match(/^users\/([^/]+)\/password$/);
    if (passwordMatch && method === 'POST') {
      if (!isManager) return json({ error: 'Sem permissão.' }, 403);
      const id = passwordMatch[1];
      const target = await env.DB.prepare(
        'SELECT id, role FROM users WHERE id = ? AND active = 1'
      ).bind(id).first();
      if (!target) return json({ error: 'Usuário não encontrado ou inativo.' }, 404);
      if (!isAdmin && target.role === 'admin') {
        return json({ error: 'Somente o Administrador pode alterar a senha de um Administrador.' }, 403);
      }
      const data = await readBody(request);
      const password = String(data.password || '');
      if (password.length < 10) {
        return json({ error: 'A nova senha deve ter pelo menos 10 caracteres.' }, 400);
      }
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const passwordHash = await hashPass(password, salt);
      await env.DB.prepare(
        'UPDATE users SET salt = ?, password_hash = ? WHERE id = ?'
      ).bind(salt, passwordHash, id).run();
      return json({ ok: true });
    }

    // Gerenciamento: administrador e professor sênior.
    if (path === 'management' && method === 'GET') {
      if (!isManager) return json({ error: 'Sem permissão.' }, 403);
      const [carsResult, usersResult] = await Promise.all([
        env.DB.prepare('SELECT * FROM cars ORDER BY model').all(),
        env.DB.prepare('SELECT id, name, username, role, active, created_at FROM users ORDER BY name').all()
      ]);
      return json({
        cars: carsResult.results || [],
        users: usersResult.resu
