const jsonHeaders = {
  "content-type": "application/json; charset=UTF-8",
  "cache-control": "no-store"
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...jsonHeaders, ...extraHeaders }
  });
}

function cors(request) {
  return {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin"
  };
}

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decode64(value) {
  let base64 = value.replace(/-/g, "+").replace(/_/g, "/");

  while (base64.length % 4) base64 += "=";

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function makeToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function hashPassword(password, saltBytes = null) {
  const encoder = new TextEncoder();

  const salt =
    saltBytes ||
    crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 210000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    salt: base64url(salt),
    hash: base64url(new Uint8Array(bits))
  };
}

async function verifyPassword(password, salt, hash) {
  const result = await hashPassword(
    password,
    decode64(salt)
  );

  return result.hash === hash;
}

function getToken(request) {
  const auth =
    request.headers.get("Authorization") || "";

  if (auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }

  return null;
}

async function currentUser(request, env) {
  const token = getToken(request);

  if (!token) return null;

  return await env.DB.prepare(`
    SELECT
      u.id,
      u.name,
      u.email,
      u.role
    FROM sessions s
    JOIN users u
      ON u.id = s.user_id
    WHERE s.id = ?
      AND datetime(s.expires_at) > datetime('now')
    LIMIT 1
  `)
    .bind(token)
    .first();
}

export default {
  async fetch(request, env) {
    const headers = cors(request);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    if (!env.DB) {
      return json(
        {
          ok: false,
          error: "Database DB is not connected."
        },
        500,
        headers
      );
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {

      // اختبار الاتصال
      if (path === "/" && request.method === "GET") {
        return json(
          {
            ok: true,
            service: "MUTLAK CAPITALS API",
            database: "connected"
          },
          200,
          headers
        );
      }

      // إنشاء حساب طالب
      if (
        path === "/api/register" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const name =
          String(body.name || "").trim();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const password =
          String(body.password || "");

        if (name.length < 2) {
          return json(
            {
              ok: false,
              error: "الاسم مطلوب"
            },
            400,
            headers
          );
        }

        if (
          !email ||
          !email.includes("@")
        ) {
          return json(
            {
              ok: false,
              error: "البريد الإلكتروني غير صحيح"
            },
            400,
            headers
          );
        }

        if (password.length < 8) {
          return json(
            {
              ok: false,
              error:
                "كلمة المرور يجب أن تكون 8 أحرف على الأقل"
            },
            400,
            headers
          );
        }

        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM users
            WHERE lower(email) = ?
            LIMIT 1
          `)
            .bind(email)
            .first();

        if (existing) {
          return json(
            {
              ok: false,
              error:
                "هذا البريد الإلكتروني مسجل مسبقاً"
            },
            409,
            headers
          );
        }

        const passwordData =
          await hashPassword(password);

        const result =
          await env.DB.prepare(`
            INSERT INTO users
            (
              name,
              email,
              password_hash,
              password_salt,
              role
            )
            VALUES (?, ?, ?, ?, 'student')
          `)
            .bind(
              name,
              email,
              passwordData.hash,
              passwordData.salt
            )
            .run();

        return json(
          {
            ok: true,
            message: "تم إنشاء الحساب بنجاح",
            user_id: result.meta.last_row_id
          },
          201,
          headers
        );
      }

      // تسجيل الدخول
      if (
        path === "/api/login" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const password =
          String(body.password || "");

        const user =
          await env.DB.prepare(`
            SELECT
              id,
              name,
              email,
              password_hash,
              password_salt,
              role
            FROM users
            WHERE lower(email) = ?
            LIMIT 1
          `)
            .bind(email)
            .first();

        if (!user) {
          return json(
            {
              ok: false,
              error:
                "البريد الإلكتروني أو كلمة المرور غير صحيحة"
            },
            401,
            headers
          );
        }

        const valid =
          await verifyPassword(
            password,
            user.password_salt,
            user.password_hash
          );

        if (!valid) {
          return json(
            {
              ok: false,
              error:
                "البريد الإلكتروني أو كلمة المرور غير صحيحة"
            },
            401,
            headers
          );
        }

        const sessionToken = makeToken();

        const expiresAt =
          new Date(
            Date.now() +
            7 * 24 * 60 * 60 * 1000
          ).toISOString();

        await env.DB.prepare(`
          INSERT INTO sessions
          (
            id,
            user_id,
            expires_at
          )
          VALUES (?, ?, ?)
        `)
          .bind(
            sessionToken,
            user.id,
            expiresAt
          )
          .run();

        return json(
          {
            ok: true,

            token: sessionToken,

            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role
            }
          },
          200,
          headers
        );
      }

      // بيانات الطالب
      if (
        path === "/api/me" &&
        request.method === "GET"
      ) {
        const user =
          await currentUser(
            request,
            env
          );

        if (!user) {
          return json(
            {
              ok: false,
              error: "يجب تسجيل الدخول"
            },
            401,
            headers
          );
        }

        return json(
          {
            ok: true,
            user
          },
          200,
          headers
        );
      }

      // تسجيل الخروج
      if (
        path === "/api/logout" &&
        request.method === "POST"
      ) {
        const token =
          getToken(request);

        if (token) {
          await env.DB.prepare(`
            DELETE FROM sessions
            WHERE id = ?
          `)
            .bind(token)
            .run();
        }

        return json(
          {
            ok: true,
            message: "تم تسجيل الخروج"
          },
          200,
          headers
        );
      }

      return json(
        {
          ok: false,
          error: "المسار غير موجود"
        },
        404,
        headers
      );

    } catch (error) {

      console.error(error);

      return json(
        {
          ok: false,
          error: "حدث خطأ في الخادم",
          detail:
            String(
              error?.message || error
            )
        },
        500,
        headers
      );
    }
  }
};
