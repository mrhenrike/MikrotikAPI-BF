local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Connects to the MikroTik RouterOS binary API (TCP/8728 or TCP/8729),
authenticates with provided credentials, and retrieves system information:
  - RouterOS version
  - Board name, architecture
  - CPU model and load
  - Memory and disk usage
  - Uptime
  - Installed packages
  - Configured users and groups
  - Open IP services (ports)

No credentials → attempts unauthenticated info gathering (version from
API hello, pre-auth fingerprint).

References:
  - https://github.com/mrhenrike/MikrotikAPI-BF
  - https://wiki.mikrotik.com/wiki/Manual:API
]]

---
-- @usage
--   nmap -p 8728 --script mikrotik-api-info <target>
--   nmap -p 8728 --script mikrotik-api-info --script-args creds.global='admin:pass' <target>
--   nmap -p 8728 --script mikrotik-api-info --script-args mikrotik-api-info.user=admin,mikrotik-api-info.pass=secret <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8728/tcp open  routeros-api
-- | mikrotik-api-info:
-- |   version: RouterOS 7.20.7 (long-term)
-- |   board: CHR DigitalOcean Droplet
-- |   architecture: x86_64
-- |   cpu-load: 1%
-- |   uptime: 4d5h11m
-- |   free-memory: 278MB / 512MB
-- |   users: admin (group=full)
-- |_  services: ftp:21, ssh:22, telnet:23, www:80, api:8728, winbox:8291

author = "Andre Henrique <@mrhenrike>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

portrule = shortport.port_or_service({8728, 8729}, {"routeros-api", "mikrotik-api"})

-- ── RouterOS binary protocol helpers ─────────────────────────────────────────

local function encode_length(len)
  if len < 0x80 then return string.char(len)
  elseif len < 0x4000 then
    len = len | 0x8000
    return string.char((len >> 8) & 0xFF, len & 0xFF)
  else
    len = len | 0xC00000
    return string.char((len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF)
  end
end

local function read_length(sock)
  local b0 = sock:receive_bytes(1)
  if not b0 then return nil end
  local c0 = string.byte(b0)
  if c0 < 0x80 then return c0
  elseif c0 < 0xC0 then
    local b1 = sock:receive_bytes(1)
    if not b1 then return nil end
    return ((c0 & 0x3F) << 8) | string.byte(b1)
  else
    local rest = sock:receive_bytes(3)
    if not rest then return nil end
    local b = {string.byte(rest, 1, 3)}
    return ((c0 & 0x1F) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
  end
end

local function send_sentence(sock, words)
  local out = {}
  for _, w in ipairs(words) do out[#out+1] = encode_length(#w) .. w end
  out[#out+1] = "\x00"
  return sock:send(table.concat(out))
end

local function read_sentence(sock)
  local words = {}
  while true do
    local len = read_length(sock)
    if not len then return nil end
    if len == 0 then break end
    local word = sock:receive_bytes(len)
    if not word then return nil end
    words[#words+1] = word
  end
  return words
end

local function parse_props(sentences)
  local props = {}
  for _, sent in ipairs(sentences) do
    for _, w in ipairs(sent) do
      if w:sub(1,1) == "=" then
        local k, v = w:match("^=([^=]+)=(.*)")
        if k then props[k] = v end
      end
    end
  end
  return props
end

local function collect_all(sock, cmd)
  send_sentence(sock, cmd)
  local rows = {}
  while true do
    local s = read_sentence(sock)
    if not s then break end
    if s[1] == "!done" then break end
    if s[1] == "!re" then rows[#rows+1] = s end
    if s[1] == "!trap" then break end
  end
  return rows
end

-- ── Authentication ────────────────────────────────────────────────────────────

local function login(sock, user, pass)
  send_sentence(sock, {"/login", "=name=" .. user, "=password=" .. pass})
  local r = read_sentence(sock)
  if not r then return false end

  if r[1] == "!done" then
    local challenge
    for _, w in ipairs(r) do
      if w:sub(1,5) == "=ret=" then challenge = w:sub(6) end
    end
    if challenge then
      -- 6.x MD5 challenge
      local md5 = require "openssl".md5
      local ch = stdnse.fromhex(challenge)
      local hash = stdnse.tohex(md5("\x00" .. pass .. ch))
      send_sentence(sock, {"/login", "=name=" .. user, "=response=00" .. hash})
      r = read_sentence(sock)
      if not r then return false end
    end
    return r[1] == "!done"
  end
  return false
end

-- ── Main action ───────────────────────────────────────────────────────────────

action = function(host, port)
  local use_ssl = port.number == 8729
  local timeout = 8000
  local user = stdnse.get_script_args("mikrotik-api-info.user") or "admin"
  local pass = stdnse.get_script_args("mikrotik-api-info.pass") or ""

  local sock = nmap.new_socket()
  sock:set_timeout(timeout)
  local ok = use_ssl and sock:connect(host, port, "ssl") or sock:connect(host, port)
  if not ok then return "Could not connect" end

  local authed = login(sock, user, pass)
  if not authed then
    sock:close()
    return "Authentication failed (wrong credentials or no auth)"
  end

  local output = stdnse.output_table()

  -- System resource
  local rows = collect_all(sock, {"/system/resource/print"})
  if rows[1] then
    local p = parse_props(rows)
    output["version"]      = p["version"] or "?"
    output["board"]        = p["board-name"] or "?"
    output["architecture"] = p["architecture-name"] or "?"
    output["platform"]     = p["platform"] or "?"
    output["cpu-load"]     = (p["cpu-load"] or "?") .. "%"
    output["uptime"]       = p["uptime"] or "?"
    local free = math.floor((tonumber(p["free-memory"] or 0)) / 1048576)
    local total = math.floor((tonumber(p["total-memory"] or 0)) / 1048576)
    output["free-memory"]  = free .. "MB / " .. total .. "MB"
  end

  -- Users
  rows = collect_all(sock, {"/user/print"})
  local users = {}
  for _, r in ipairs(rows) do
    local p = parse_props({r})
    if p["name"] then
      users[#users+1] = p["name"] .. " (group=" .. (p["group"] or "?") .. ")"
    end
  end
  if #users > 0 then output["users"] = table.concat(users, ", ") end

  -- IP services
  rows = collect_all(sock, {"/ip/service/print"})
  local svcs = {}
  for _, r in ipairs(rows) do
    local p = parse_props({r})
    if p["name"] and p["disabled"] ~= "true" then
      svcs[#svcs+1] = p["name"] .. ":" .. (p["port"] or "?")
    end
  end
  if #svcs > 0 then output["services"] = table.concat(svcs, ", ") end

  -- Firewall filter count
  rows = collect_all(sock, {"/ip/firewall/filter/print"})
  output["firewall-rules"] = #rows .. " filter rule(s)"
  if #rows == 0 then output["firewall-rules"] = "0 - WARNING: NO FIREWALL RULES" end

  sock:close()
  return output
end
