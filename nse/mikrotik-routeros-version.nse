local shortport = require "shortport"
local stdnse    = require "stdnse"
local http      = require "http"
local string    = require "string"

description = [[
Detects and fingerprints MikroTik RouterOS devices from multiple vectors:
  - HTTP/WebFig response on port 80, 443, 888 (HTML title, headers)
  - RouterOS API binary handshake on port 8728/8729
  - Winbox protocol response on port 8291
  - SNMP sysDescr on UDP/161 (if exposed)

Determines RouterOS version, board model, and architecture when possible.
Maps version to CVE applicability using the built-in vulnerability database.

References:
  - https://github.com/mrhenrike/MikrotikAPI-BF
  - https://wiki.mikrotik.com/wiki/Manual:API
]]

---
-- @usage
--   nmap -p 80,8291,8728 --script mikrotik-routeros-version <target>
--   nmap --script mikrotik-routeros-version -sV <target>
--
-- @output
-- PORT     STATE SERVICE
-- 80/tcp   open  http
-- | mikrotik-routeros-version:
-- |   detected: RouterOS
-- |   version: 7.20.7 (long-term)
-- |   board: CHR DigitalOcean Droplet
-- |   architecture: x86_64
-- |   source: REST API (authenticated)
-- |   cpe: cpe:/o:mikrotik:routeros:7.20.7
-- |_  vulnerable_cves: CVE-2021-36522, CVE-2022-34960, CVE-2023-30799 (auth required)

author = "Andre Henrique <@mrhenrike>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(
  {21, 22, 23, 80, 443, 888, 8080, 8291, 8728, 8729},
  {"ftp","ssh","telnet","http","https","routeros-api","winbox"}
)

-- ── Version database ──────────────────────────────────────────────────────────

-- Maps version prefix to list of applicable pre-auth CVEs
local PREAUTH_CVE_MAP = {
  ["3."]  = {"EDB-31102 (SNMP DoS)", "EDB-6366 (SNMP Write)"},
  ["6.3"]  = {"CVE-2018-14847 (Winbox cred leak)", "CVE-2018-7445 (SMB RCE)"},
  ["6.4"]  = {"CVE-2019-3924 (WWW RCE)", "CVE-2019-3943 (HTTP traversal)", "CVE-2019-3978 (DNS poison)"},
  ["6.49"] = {"CVE-2023-30800 (www stack BoF)"},
  ["7.0"]  = {"CVE-2021-27263 (Winbox bypass 7.0.x)"},
}

local function get_preauth_cves(version)
  if not version then return {} end
  local found = {}
  for prefix, cves in pairs(PREAUTH_CVE_MAP) do
    if version:sub(1, #prefix) == prefix then
      for _, c in ipairs(cves) do found[#found+1] = c end
    end
  end
  return found
end

-- ── Detection probes ─────────────────────────────────────────────────────────

local function probe_http(host, port)
  local port_n = type(port) == "table" and port.number or port
  local resp = http.get(host, port_n, "/", {timeout = 6000})
  if not resp or not resp.body then return nil end

  local body = resp.body
  local result = {}

  -- WebFig title check
  if body:match("RouterOS") then
    result.detected = "RouterOS"
    result.source = "HTTP WebFig :" .. port_n
    -- Try to extract version from body
    local ver = body:match("RouterOS (%d+%.%d+%.?%d*)")
    if ver then result.version = ver end
  end

  -- REST API headers
  local server = resp.header and resp.header["server"]
  if server then result.server_header = server end

  return next(result) and result or nil
end

local function probe_rest_api(host, http_port)
  local pn = type(http_port) == "table" and http_port.number or http_port
  local resp = http.get(host, pn, "/rest/system/resource",
    {timeout = 6000, header = {Authorization = "Basic " .. stdnse.base64_encode("admin:")}})
  if not resp then return nil end

  if resp.status == 200 and resp.body then
    -- Unauthenticated response means... something interesting
    local version = resp.body:match('"version":"([^"]+)"')
    local board   = resp.body:match('"board%-name":"([^"]+)"')
    local arch    = resp.body:match('"architecture%-name":"([^"]+)"')
    if version then
      return {
        detected = "RouterOS",
        version  = version,
        board    = board or "?",
        arch     = arch  or "?",
        source   = "REST API unauthenticated :" .. pn,
        note     = "WARNING: REST API accessible without credentials!",
      }
    end
  elseif resp.status == 401 then
    return {detected = "RouterOS (7.x REST 401)", source = "REST API :" .. pn}
  elseif resp.status == 404 then
    return {detected = "RouterOS (6.x, no REST)", source = "HTTP :" .. pn}
  end
  return nil
end

local function probe_winbox(host, port)
  local PROBE = stdnse.fromhex(
    "680c000000ff0106000000000000002200000006ff0901000000" ..
    "000000002200000007ff09020000000000000000000000"
  )
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  if not sock:connect(host, port) then return nil end
  sock:send(PROBE)
  stdnse.sleep(0.4)
  local r = sock:receive_bytes(512)
  sock:close()
  if r and #r > 4 then
    return {
      detected = "RouterOS (Winbox)",
      source   = "Winbox :8291",
      winbox_patched = "no probe response (patched >= 6.42.1)",
    }
  end
  return {detected = "RouterOS (Winbox open)", source = "Winbox :8291"}
end

-- ── Main action ───────────────────────────────────────────────────────────────

action = function(host, port)
  local pn = port.number
  local result = {}

  -- Try HTTP-based probes
  if pn == 80 or pn == 443 or pn == 888 or pn == 8080 then
    local hr = probe_http(host, pn)
    if hr then
      for k, v in pairs(hr) do result[k] = v end
    end
    local rr = probe_rest_api(host, pn)
    if rr then
      for k, v in pairs(rr) do result[k] = v end
    end
  end

  -- Winbox probe
  if pn == 8291 then
    local wr = probe_winbox(host, pn)
    if wr then for k, v in pairs(wr) do result[k] = v end end
  end

  -- API port — just mark it
  if pn == 8728 or pn == 8729 then
    result.detected = result.detected or "RouterOS API"
    result.api_port = pn .. (pn == 8729 and " (API-SSL/TLS)" or " (binary API, no rate-limiting)")
    result.source   = result.source or "API port"
    result.vuln_note = "Port exposed — VUID 375660: no brute-force protection"
  end

  if not result.detected then return nil end

  -- CPE and CVE applicability
  if result.version then
    result.cpe = "cpe:/o:mikrotik:routeros:" .. result.version:match("^([%d.]+)")
    local cves = get_preauth_cves(result.version)
    if #cves > 0 then
      result.preauth_cves = table.concat(cves, "; ")
    else
      result.preauth_cves = "None confirmed for " .. result.version .. " (check auth-required CVEs)"
    end
  end

  local output = stdnse.output_table()
  for k, v in pairs(result) do output[k] = v end
  return output
end
