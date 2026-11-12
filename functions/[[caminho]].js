
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
    'raw',
    enc.encode(pass),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  return b64(await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: enc.encode(salt),
    iterations: 210000,
    hash: 'SHA-256'
  }, key, 256));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  return b64(await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(value)
  ));
}

function cookieVal(req, name) {
  return (req.headers.get('Cookie') || '')
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith(name + '='))
    ?.slice(name.length + 1);
}

function cookie(value, maxAge = 86400) {
  return `mh_session=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function session(req, env) {
  const raw = cookieVal(req, 'mh_session');

  if (!raw || !env.SESSION_SECRET) return null;

  try {
    const [id, exp, sig] = raw.split('.');

    if (!id || !exp || !sig || Number(exp) < Date.now()) {
      return null;
    }

    const value = id + '.' + exp;

    if (await sign(value, env.SESSION_SECRET) !== sig) {
      return null;
    }

    return await env.DB.prepare(
      'SELECT id,name,username,role FROM users WHERE id=? AND active=1'
    ).bind(id).first();
  } catch {
    return null;
  }
}

async function body(req) {
  if (!req.headers.get('content-type')?.includes('application/json')) {
    return {};
  }
  return req.json();
}

function allowed(user, roles) {
  return !!user && roles.includes(user.role);
}

function dateBR(iso) {
  return iso
    ? new Date(iso).toLocaleString('pt-BR', {
        timeZone: 'America/Sao_Paulo'
      })
    : '';
}

function cleanText(value) {
  return String(value || '').trim();
}

function errorMessage(error) {
  const message = error?.message || '';

  if (message.includes('UNIQUE constraint failed')) {
    return 'Esse usuário ou placa já está cadastrado.';
  }

  if (message.includes('FOREIGN KEY constraint failed')) {
    return 'Não foi possível concluir: existem registros relacionados.';
  }

  return message || 'Erro interno.';
}

export async function onRequest({ request, env }) {
  try {
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api\/?/, '');
    const method = request.method;

    // CONFIGURAÇÃO INICIAL
    if (path === 'setup-status' && method === 'GET') {
      const result = await env.DB.prepare(
        "SELECT COUNT(*) n FROM users WHERE role='admin'"
      ).first();

      return json({ setupRequired: !result.n });
    }

    // CRIAR PRIMEIRO ADMINISTRADOR
    if (path === 'setup' && method === 'POST') {
      const d = await body(request);

      if (!env.SETUP_KEY || d.setupKey !== env.SETUP_KEY) {
        return json({ error: 'Chave de configuração inválida.' }, 403);
      }

      const count = await env.DB.prepare(
        "SELECT COUNT(*) n FROM users WHERE role='admin'"
      ).first();

      if (count.n) {
        return json({ error: 'A configuração inicial já foi concluída.' }, 409);
      }

      const name = cleanText(d.name);
      const username = cleanText(d.username).toLowerCase();
      const password = String(d.password || '');

      if (!name || !username || password.length < 10) {
        return json({
          error: 'Informe nome, usuário e senha com pelo menos 10 caracteres.'
        }, 400);
      }

      const id = uid();
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const hash = await hashPass(password, salt);

      await env.DB.prepare(
        `INSERT INTO users
        (id,name,username,role,salt,password_hash,active,created_at)
        VALUES(?,?,?,?,?,?,1,?)`
      ).bind(
        id, name, username, 'admin', salt, hash,
        new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // LOGIN
    if (path === 'login' && method === 'POST') {
      const d = await body(request);
      const username = cleanText(d.username).toLowerCase();

      const user = await env.DB.prepare(
        'SELECT * FROM users WHERE username=? AND active=1'
      ).bind(username).first();

      if (
        !user ||
        await hashPass(String(d.password || ''), user.salt) !== user.password_hash
      ) {
        return json({ error: 'Usuário ou senha incorretos.' }, 401);
      }

      if (!env.SESSION_SECRET) {
        return json({ error: 'Configuração de sessão não encontrada.' }, 500);
      }

      const exp = Date.now() + 86400000;
      const value = user.id + '.' + exp;
      const sig = await sign(value, env.SESSION_SECRET);

      return json(
        { ok: true },
        200,
        { 'set-cookie': cookie(value + '.' + sig) }
      );
    }

    // SAIR
    if (path === 'logout' && method === 'POST') {
      return json(
        { ok: true },
        200,
        { 'set-cookie': cookie('', 0) }
      );
    }

    // USUÁRIO ATUAL
    if (path === 'me' && method === 'GET') {
      const user = await session(request, env);

      if (!user) {
        return json({ error: 'Não autenticado.' }, 401);
      }

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

    // TODAS AS OUTRAS ROTAS EXIGEM LOGIN
    const user = await session(request, env);

    if (!user) {
      return json({ error: 'Não autenticado.' }, 401);
    }

    const isManager = allowed(user, ['admin', 'supervisor']);
    const isAdmin = user.role === 'admin';

    // PAINEL PRINCIPAL - TODOS PODEM CONSULTAR
    if (path === 'dashboard' && method === 'GET') {
      const [cars, checks, incidents, recent] = await Promise.all([
        env.DB.prepare(
          'SELECT * FROM cars WHERE active=1 ORDER BY model'
        ).all(),

        env.DB.prepare(
          'SELECT COUNT(*) n FROM checks'
        ).first(),

        env.DB.prepare(
          'SELECT COUNT(*) n FROM incidents'
        ).first(),

        env.DB.prepare(`
          SELECT * FROM (
            SELECT
              'Vistoria' kind,
              c.model || ' · ' || c.plate car,
              ck.created_at date,
              us.name author
            FROM checks ck
            JOIN cars c ON c.id=ck.car_id
            JOIN users us ON us.id=ck.user_id

            UNION ALL

            SELECT
              'Ocorrência' kind,
              c.model || ' · ' || c.plate car,
              i.created_at date,
              us.name author
            FROM incidents i
            JOIN cars c ON c.id=i.car_id
            JOIN users us ON us.id=i.user_id
          )
          ORDER BY date DESC
          LIMIT 8
        `).all()
      ]);

      return json({
        cars: cars.results,
        checks: checks.n,
        incidents: incidents.n,
        recent: recent.results.map(x => ({
          ...x,
          date: dateBR(x.date)
        }))
      });
    }

    // CHECKLIST - TODOS PODEM FAZER
    if (path === 'checks' && method === 'POST') {
      const d = await body(request);
      const km = Number(d.km);

      if (!d.car_id || !Number.isFinite(km) || km < 0) {
        return json({
          error: 'Veículo e quilometragem válidos são obrigatórios.'
        }, 400);
      }

      const car = await env.DB.prepare(
        'SELECT id FROM cars WHERE id=? AND active=1'
      ).bind(d.car_id).first();

      if (!car) {
        return json({ error: 'Veículo não encontrado ou inativo.' }, 400);
      }

      const id = uid();
      const now = new Date().toISOString();

      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO checks
          (id,car_id,user_id,km,tires,oil,fuel,clean,notes,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?)`
        ).bind(
          id,
          d.car_id,
          user.id,
          km,
          +!!d.tires,
          +!!d.oil,
          +!!d.fuel,
          +!!d.clean,
          cleanText(d.notes),
          now
        ),

        env.DB.prepare(
          'UPDATE cars SET km=? WHERE id=?'
        ).bind(km, d.car_id)
      ]);

      return json({ ok: true });
    }

    // OCORRÊNCIAS - ADMINISTRADOR E PROFESSOR SÊNIOR
    if (path === 'incidents' && method === 'POST') {
      if (!isManager) {
        return json({ error: 'Sem permissão para registrar ocorrências.' }, 403);
      }

      const d = await body(request);

      if (!d.car_id || !cleanText(d.description) || !cleanText(d.severity)) {
        return json({
          error: 'Preencha veículo, gravidade e descrição.'
        }, 400);
      }

      const car = await env.DB.prepare(
        'SELECT id FROM cars WHERE id=? AND active=1'
      ).bind(d.car_id).first();

      if (!car) {
        return json({ error: 'Veículo não encontrado ou inativo.' }, 400);
      }

      await env.DB.prepare(
        `INSERT INTO incidents
        (id,car_id,user_id,severity,description,created_at)
        VALUES(?,?,?,?,?,?)`
      ).bind(
        uid(),
        d.car_id,
        user.id,
        cleanText(d.severity),
        cleanText(d.description),
        new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // HISTÓRICO - TODOS PODEM CONSULTAR
    if (path === 'history' && method === 'GET') {
      const type = url.searchParams.get('type') || 'all';
      const car = url.searchParams.get('car');
      const from = url.searchParams.get('from');
      const to = url.searchParams.get('to');
      const rows = [];

      if (type !== 'incident') {
        let query = `
          SELECT
            ck.id,
            'Vistoria' kind,
            c.model || ' · ' || c.plate car,
            ck.created_at date,
            u.name author,
            ck.km,
            ck.notes summary,
            NULL incident_id
          FROM checks ck
          JOIN cars c ON c.id=ck.car_id
          JOIN users u ON u.id=ck.user_id
          WHERE 1=1
        `;
        const params = [];

        if (car) {
          query += ' AND ck.car_id=?';
          params.push(car);
        }
        if (from) {
          query += ' AND date(ck.created_at)>=date(?)';
          params.push(from);
        }
        if (to) {
          query += ' AND date(ck.created_at)<=date(?)';
          params.push(to);
        }

        const result = await env.DB.prepare(query).bind(...params).all();
        rows.push(...result.results);
      }

      if (type !== 'check') {
        let query = `
          SELECT
            i.id,
            'Ocorrência' kind,
            c.model || ' · ' || c.plate car,
            i.created_at date,
            u.name author,
            NULL km,
            i.severity || ': ' || i.description summary,
            i.id incident_id
          FROM incidents i
          JOIN cars c ON c.id=i.car_id
          JOIN users u ON u.id=i.user_id
          WHERE 1=1
        `;
        const params = [];

        if (car) {
          query += ' AND i.car_id=?';
          params.push(car);
        }
        if (from) {
          query += ' AND date(i.created_at)>=date(?)';
          params.push(from);
        }
        if (to) {
          query += ' AND date(i.created_at)<=date(?)';
          params.push(to);
        }

        const result = await env.DB.prepare(query).bind(...params).all();
        rows.push(...result.results);
      }

      rows.sort((a, b) => b.date.localeCompare(a.date));

      for (const row of rows) {
        row.date = dateBR(row.date);
        row.files = [];
      }

      return json({ rows });
    }

    // CADASTRAR CARRO - ADMINISTRADOR E PROFESSOR SÊNIOR
    if (path === 'cars' && method === 'POST') {
      if (!isManager) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const d = await body(request);
      const model = cleanText(d.model);
      const plate = cleanText(d.plate).toUpperCase();
      const km = Number(d.km) || 0;

      if (!model || !plate || !Number.isFinite(km) || km < 0) {
        return json({ error: 'Informe modelo, placa e quilometragem válida.' }, 400);
      }

      await env.DB.prepare(
        `INSERT INTO cars(id,model,plate,km,active,created_at)
         VALUES(?,?,?,?,1,?)`
      ).bind(
        uid(), model, plate, km, new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // EDITAR OU EXCLUIR CARRO
    const carMatch = path.match(/^cars\/([^/]+)$/);

    if (carMatch && ['PATCH', 'DELETE'].includes(method)) {
      if (!isManager) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const id = carMatch[1];

      const existing = await env.DB.prepare(
        'SELECT id FROM cars WHERE id=?'
      ).bind(id).first();

      if (!existing) {
        return json({ error: 'Carro não encontrado.' }, 404);
      }

      if (method === 'DELETE') {
        await env.DB.prepare(
          'UPDATE cars SET active=0 WHERE id=?'
        ).bind(id).run();

        return json({ ok: true });
      }

      const d = await body(request);
      const model = cleanText(d.model);
      const plate = cleanText(d.plate).toUpperCase();
      const km = Number(d.km);

      if (!model || !plate || !Number.isFinite(km) || km < 0) {
        return json({ error: 'Informe modelo, placa e quilometragem válida.' }, 400);
      }

      await env.DB.prepare(
        'UPDATE cars SET model=?,plate=?,km=? WHERE id=?'
      ).bind(model, plate, km, id).run();

      return json({ ok: true });
    }

    // CADASTRAR USUÁRIO
    if (path === 'users' && method === 'POST') {
      if (!isManager) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const d = await body(request);
      const name = cleanText(d.name);
      const username = cleanText(d.username).toLowerCase();
      const password = String(d.password || '');
      const role = cleanText(d.role);

      if (
        !name ||
        !username ||
        password.length < 10 ||
        !ROLES.includes(role)
      ) {
        return json({
          error: 'Informe nome, usuário, perfil e senha com pelo menos 10 caracteres.'
        }, 400);
      }

      // Professor Sênior não pode criar outro administrador.
      if (!isAdmin && role === 'admin') {
        return json({
          error: 'Somente o Administrador pode criar outro Administrador.'
        }, 403);
      }

      const id = uid();
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const hash = await hashPass(password, salt);

      await env.DB.prepare(
        `INSERT INTO users
        (id,name,username,role,salt,password_hash,active,created_at)
        VALUES(?,?,?,?,?,?,1,?)`
      ).bind(
        id,
        name,
        username,
        role,
        salt,
        hash,
        new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // EDITAR OU EXCLUIR USUÁRIO
    const userMatch = path.match(/^users\/([^/]+)$/);

    if (userMatch && ['PATCH', 'DELETE'].includes(method)) {
      if (!isManager) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const id = userMatch[1];

      const target = await env.DB.prepare(
        'SELECT id,name,username,role,active FROM users WHERE id=?'
      ).bind(id).first();

      if (!target) {
        return json({ error: 'Usuário não encontrado.' }, 404);
      }

      // O Professor Sênior não pode alterar ou excluir administradores.
      if (!isAdmin && target.role === 'admin') {
        return json({
          error: 'Somente o Administrador pode alterar a conta de um Administrador.'
        }, 403);
      }

      // Não permitir desativar a própria conta.
      if (method === 'DELETE') {
        if (id === user.id) {
          return json({
            error: 'Você não pode excluir seu próprio usuário enquanto estiver conectado.'
          }, 400);
        }

        if (target.role === 'admin') {
          const admins = await env.DB.prepare(
            "SELECT COUNT(*) n FROM users WHERE role='admin' AND active=1"
          ).first();

          if (admins.n <= 1) {
            return json({
              error: 'Não é possível desativar o último Administrador.'
            }, 400);
          }
        }

        await env.DB.prepare(
          'UPDATE users SET active=0 WHERE id=?'
        ).bind(id).run();

        return json({ ok: true });
      }

      const d = await body(request);
      const name = cleanText(d.name);
      const username = cleanText(d.username).toLowerCase();
      const role = cleanText(d.role);

      if (!name || !username || !ROLES.includes(role)) {
        return json({
          error: 'Informe nome, usuário e perfil válidos.'
        }, 400);
      }

      if (!isAdmin && role === 'admin') {
        return json({
          error: 'Somente o Administrador pode definir o perfil Administrador.'
        }, 403);
      }

      if (id === user.id && role !== user.role) {
        return json({
          error: 'Não é possível alterar o próprio perfil.'
        }, 400);
      }

      await env.DB.prepare(
        'UPDATE users SET name=?,username=?,role=? WHERE id=?'
      ).bind(name, username, role, id).run();

      return json({ ok: true });
    }

    // REDEFINIR SENHA DE USUÁRIO
    const passwordMatch = path.match(/^users\/([^/]+)\/password$/);

    if (passwordMatch && method === 'POST') {
      if (!isManager) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const id = passwordMatch[1];
      const target = await env.DB.prepare(
        'SELECT id,role FROM users WHERE id=? AND active=1'
      ).bind(id).first();

      if (!target) {
        return json({ error: 'Usuário não encontrado ou inativo.' }, 404);
      }

      if (!isAdmin && target.role === 'admin') {
        return json({
          error: 'Somente o Administrador pode alterar a senha de um Administrador.'
        }, 403);
      }

      const d = await body(request);
      const password = String(d.password || '');

      if (password.length < 10) {
        return json({
          error: 'A nova senha deve ter pelo menos 10 caracteres.'
        }, 400);
      }

      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const hash = await hashPass(password, salt);

      await env.DB.prepare(
        'UPDATE users SET salt=?,password_hash=? WHERE id=?'
      ).bind(salt, hash, id).run();

      return json({ ok: true });
    }

    // GERENCIAMENTO - ADMINISTRADOR E PROFESSOR SÊNIOR
    if (path === 'management' && method === 'GET') {
      if (!isManager) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const [cars, users] = await Promise.all([
        env.DB.prepare(
          'SELECT * FROM cars ORDER BY model'
        ).all(),

        env.DB.prepare(
          'SELECT id,name,username,role,active FROM users ORDER BY name'
        ).all()
      ]);

      return json({
        cars: cars.results,
        users: users.results
      });
    }

    // RELATÓRIOS - SOMENTE ADMINISTRADOR
    if (path === 'reports' && method === 'GET') {
      if (!isAdmin) {
        return json({
          error: 'Somente o Administrador pode emitir relatórios.'
        }, 403);
      }

      const monthValue = url.searchParams.get('month');

      if (!/^\d{4}-\d{2}$/.test(monthValue || '')) {
        return 
