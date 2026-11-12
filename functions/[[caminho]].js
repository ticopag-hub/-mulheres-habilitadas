
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store'
    }
  });

const enc = new TextEncoder();

const b64 = b =>
  btoa(String.fromCharCode(...new Uint8Array(b)))
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

  return b64(
    await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: enc.encode(salt),
        iterations: 210000,
        hash: 'SHA-256'
      },
      key,
      256
    )
  );
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  return b64(
    await crypto.subtle.sign('HMAC', key, enc.encode(value))
  );
}

function cookieVal(req, name) {
  return (req.headers.get('Cookie') || '')
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith(name + '='))
    ?.slice(name.length + 1);
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

function cookie(value, maxAge = 86400) {
  return `mh_session=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

const uid = () => crypto.randomUUID();

async function body(req) {
  return req.headers.get('content-type')?.includes('application/json')
    ? req.json()
    : {};
}

function allowed(user, roles) {
  return user && roles.includes(user.role);
}

async function need(req, env, roles = ['admin', 'supervisor', 'instructor']) {
  const u = await session(req, env);

  if (!allowed(u, roles)) {
    throw new Error('Acesso não autorizado.');
  }

  return u;
}

function dateBR(iso) {
  return iso
    ? new Date(iso).toLocaleString('pt-BR', {
        timeZone: 'America/Sao_Paulo'
      })
    : '';
}

export async function onRequest({ request, env }) {
  try {
    const path = new URL(request.url).pathname.replace(/^\/api\/?/, '');
    const method = request.method;

    // VERIFICAÇÃO DA CONFIGURAÇÃO INICIAL
    if (path === 'setup-status' && method === 'GET') {
      const r = await env.DB.prepare(
        "SELECT COUNT(*) n FROM users WHERE role='admin'"
      ).first();

      return json({ setupRequired: !r.n });
    }

    // CRIAÇÃO DO PRIMEIRO ADMINISTRADOR
    if (path === 'setup' && method === 'POST') {
      const d = await body(request);

      if (!env.SETUP_KEY || d.setupKey !== env.SETUP_KEY) {
        return json({ error: 'Chave de configuração inválida.' }, 403);
      }

      const n = await env.DB.prepare(
        "SELECT COUNT(*) n FROM users WHERE role='admin'"
      ).first();

      if (n.n) {
        return json({
          error: 'A configuração inicial já foi concluída.'
        }, 409);
      }

      if (!d.name || !d.username || !d.password || d.password.length < 10) {
        return json({
          error: 'Informe nome, usuário e senha com pelo menos 10 caracteres.'
        }, 400);
      }

      const id = uid();
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const hash = await hashPass(d.password, salt);

      await env.DB.prepare(
        'INSERT INTO users(id,name,username,role,salt,password_hash,active,created_at) VALUES(?,?,?,?,?,?,1,?)'
      ).bind(
        id,
        d.name,
        d.username.toLowerCase(),
        'admin',
        salt,
        hash,
        new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // LOGIN
    if (path === 'login' && method === 'POST') {
      const d = await body(request);

      const u = await env.DB.prepare(
        'SELECT * FROM users WHERE username=? AND active=1'
      ).bind(String(d.username || '').toLowerCase()).first();

      if (
        !u ||
        await hashPass(String(d.password || ''), u.salt) !== u.password_hash
      ) {
        return json({
          error: 'Usuário ou senha incorretos.'
        }, 401);
      }

      if (!env.SESSION_SECRET) {
        return json({
          error: 'Configuração de sessão não encontrada.'
        }, 500);
      }

      const exp = Date.now() + 86400000;
      const value = u.id + '.' + exp;
      const sig = await sign(value, env.SESSION_SECRET);

      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'content-type': 'application/json',
          'cache-control': 'no-store',
          'set-cookie': cookie(value + '.' + sig)
        }
      });
    }

    // LOGOUT
    if (path === 'logout' && method === 'POST') {
      return new Response('{"ok":true}', {
        headers: {
          'content-type': 'application/json',
          'set-cookie': cookie('', 0)
        }
      });
    }

    // USUÁRIO LOGADO
    if (path === 'me') {
      const u = await session(request, env);

      return u
        ? json({
            user: {
              ...u,
              roleLabel: {
                admin: 'Administrador',
                supervisor: 'Supervisor',
                instructor: 'Instrutor'
              }[u.role]
            }
          })
        : json({ error: 'Não autenticado' }, 401);
    }

    const u = await need(request, env);

    // PAINEL PRINCIPAL
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
              'Ocorrência',
              c.model || ' · ' || c.plate,
              i.created_at,
              us.name
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

    // REGISTRO DE VISTORIA
    if (path === 'checks' && method === 'POST') {
      const d = await body(request);

      if (
        !d.car_id ||
        !Number.isFinite(d.km) ||
        d.km < 0
      ) {
        return json({
          error: 'Veículo e quilometragem válidos são obrigatórios.'
        }, 400);
      }

      const id = uid();
      const now = new Date().toISOString();

      await env.DB.batch([
        env.DB.prepare(
          'INSERT INTO checks(id,car_id,user_id,km,tires,oil,fuel,clean,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)'
        ).bind(
          id,
          d.car_id,
          u.id,
          d.km,
          +!!d.tires,
          +!!d.oil,
          +!!d.fuel,
          +!!d.clean,
          d.notes || '',
          now
        ),

        env.DB.prepare(
          'UPDATE cars SET km=? WHERE id=?'
        ).bind(d.km, d.car_id)
      ]);

      return json({ ok: true });
    }

    // REGISTRO DE OCORRÊNCIA SEM FOTOS OU DOCUMENTOS
    if (path === 'incidents' && method === 'POST') {
      const d = await body(request);

      if (!d.car_id || !d.description || !d.severity) {
        return json({
          error: 'Preencha veículo, gravidade e descrição.'
        }, 400);
      }

      const id = uid();
      const now = new Date().toISOString();

      await env.DB.prepare(
        'INSERT INTO incidents(id,car_id,user_id,severity,description,created_at) VALUES(?,?,?,?,?,?)'
      ).bind(
        id,
        d.car_id,
        u.id,
        d.severity,
        d.description,
        now
      ).run();

      return json({ ok: true });
    }

    // HISTÓRICO
    if (path === 'history' && method === 'GET') {
      const url = new URL(request.url);

      const type = url.searchParams.get('type') || 'all';
      const car = url.searchParams.get('car');
      const from = url.searchParams.get('from');
      const to = url.searchParams.get('to');

      const rows = [];

      // VISTORIAS
      if (type !== 'incident') {
        let q = `
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

        const p = [];

        if (car) {
          q += ' AND ck.car_id=?';
          p.push(car);
        }

        if (from) {
          q += ' AND date(ck.created_at)>=date(?)';
          p.push(from);
        }

        if (to) {
          q += ' AND date(ck.created_at)<=date(?)';
          p.push(to);
        }

        const x = await env.DB.prepare(q).bind(...p).all();
        rows.push(...x.results);
      }

      // OCORRÊNCIAS
      if (type !== 'check') {
        let q = `
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

        const p = [];

        if (car) {
          q += ' AND i.car_id=?';
          p.push(car);
        }

        if (from) {
          q += ' AND date(i.created_at)>=date(?)';
          p.push(from);
        }

        if (to) {
          q += ' AND date(i.created_at)<=date(?)';
          p.push(to);
        }

        const x = await env.DB.prepare(q).bind(...p).all();
        rows.push(...x.results);
      }

      rows.sort((a, b) => b.date.localeCompare(a.date));

      for (const r of rows) {
        r.date = dateBR(r.date);
        r.files = [];
      }

      return json({ rows });
    }

    // CADASTRO DE VEÍCULOS
    if (path === 'cars' && method === 'POST') {
      if (!allowed(u, ['admin', 'supervisor'])) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const d = await body(request);

      if (!d.model || !d.plate) {
        return json({
          error: 'Modelo e placa são obrigatórios.'
        }, 400);
      }

      await env.DB.prepare(
        'INSERT INTO cars(id,model,plate,km,active,created_at) VALUES(?,?,?,?,1,?)'
      ).bind(
        uid(),
        d.model,
        d.plate.toUpperCase(),
        Number(d.km) || 0,
        new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // CADASTRO DE USUÁRIOS
    if (path === 'users' && method === 'POST') {
      if (!allowed(u, ['admin'])) {
        return json({
          error: 'Somente administrador pode criar usuários.'
        }, 403);
      }

      const d = await body(request);

      if (
        !d.name ||
        !d.username ||
        !d.password ||
        d.password.length < 10 ||
        !['admin', 'supervisor', 'instructor'].includes(d.role)
      ) {
        return json({
          error: 'Dados inválidos. Senha deve ter ao menos 10 caracteres.'
        }, 400);
      }

      const id = uid();
      const salt = b64(
        crypto.getRandomValues(new Uint8Array(16))
      );

      const hash = await hashPass(d.password, salt);

      await env.DB.prepare(
        'INSERT INTO users(id,name,username,role,salt,password_hash,active,created_at) VALUES(?,?,?,?,?,?,1,?)'
      ).bind(
        id,
        d.name,
        d.username.toLowerCase(),
        d.role,
        salt,
        hash,
        new Date().toISOString()
      ).run();

      return json({ ok: true });
    }

    // GERENCIAMENTO
    if (path === 'management' && method === 'GET') {
      if (!allowed(u, ['admin', 'supervisor'])) {
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

    // RELATÓRIOS MENSAIS
    if (path === 'reports' && method === 'GET') {
      if (!allowed(u, ['admin', 'supervisor'])) {
        return json({ error: 'Sem permissão.' }, 403);
      }

      const m = new URL(request.url).searchParams.get('month');

      if (!/^\d{4}-\d{2}$/.test(m || '')) {
        return json({
          error: 'Informe mês no formato AAAA-MM.'
        }, 400);
      }

      const year = Number(m.slice(0, 4));
      const month = Number(m.slice(5, 7));

      if (month < 1 || month > 12) {
        return json({ error: 'Mês inválido.' }, 400);
      }

      const start = m + '-01';
      const end = new Date(Date.UTC(year, month, 1))
        .toISOString()
        .slice(0, 10);

      const [checks, incidents] = await Promise.all([
        env.DB.prepare(`
          SELECT
            ck.*,
            c.model || ' · ' || c.plate car,
            u.name author
          FROM checks ck
          JOIN cars c ON c.id=ck.car_id
          JOIN users u ON u.id=ck.user_id
          WHERE date(ck.created_at)>=date(?)
            AND date(ck.created_at)<date(?)
          ORDER BY ck.created_at
        `).bind(start, end).all(),

        env.DB.prepare(`
          SELECT
            i.*,
            c.model || ' · ' || c.plate car,
            u.name author
          FROM incidents i
          JOIN cars c ON c.id=i.car_id
          JOIN users u ON u.id=i.user_id
          WHERE date(i.created_at)>=date(?)
            AND date(i.created_at)<date(?)
          ORDER BY i.created_at
        `).bind(start, end).all()
      ]);

      return json({
        month: m,
        checks: checks.results.map(x => ({
          ...x,
          date: dateBR(x.created_at)
        })),
        incidents: incidents.results.map(x => ({
          ...x,
          date: dateBR(x.created_at)
        }))
      });
    }

    return json({
      error: 'Rota não encontrada.'
    }, 404);

  } catch (e) {
    return json({
      error: e.message || 'Erro interno.'
    }, 500);
  }
     }
   
