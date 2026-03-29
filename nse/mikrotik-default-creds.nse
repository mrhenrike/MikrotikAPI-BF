local shortport = require "shortport"
local creds     = require "creds"
local stdnse    = require "stdnse"
local http      = require "http"
local string    = require "string"
local table     = require "table"

description = [[
Tests MikroTik RouterOS devices for default, empty, and well-known credentials
across all management interfaces simultaneously:
  - RouterOS API binary (TCP/8728, TCP/8729)
  - REST API over HTTP/HTTPS (TCP/80, TCP/443)

Default credential list includes:
  admin: (empty password — RouterOS factory default)
  admin:admin
  admin:mikrotik
  admin:1234
  admin:12345
  admin:123456
  admin:password
  admin:changeme
  admin:routeros
  admin:router

References:
  - https://github.com/mrhenrike/MikrotikAPI-BF
  - https://kb.cert.org/vince/comm/ (VUID 375660)
]]

---
-- @usage
--   nmap -p 8728,80 --script mikrotik-default-creds <target>
--   nmap -p 8728 --script mikrotik-default-creds --script-args mikrotik-default-creds.extra='admin:secret,guest:guest' <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8728/tcp open  routeros-api
-- | mikrotik-default-creds:
-- |   CREDENTIALS FOUND
-- |     admin:  (empty password) — API:8728, REST:80
-- |_  RouterOS 7.20.7 | Board: CHR DigitalOcean Droplet

author = "Andre Henrique <@mrhenrike>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"auth", "default", "safe"}

portrule = shortport.port_or_service({8728, 8729, 80, 443}, {"routeros-api","http","https"})

-- Built-in default credential list
local DEFAULT_CREDS = {
  {"admin", ""},
  {"admin", "admin"},
  {"admin", "mikrotik"},
  {"admin", "1234"},
  {"admin", "12345"},
  {"admin", "123456"},
  {"admin", "password"},
  {"admin", "changeme"},
  {"admin", "routeros"},
  {"admin", "router"},
}

-- ── RouterOS binary API auth ──────────────────────────────────────────────────

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
  if not b0 or type(b0) ~= "string" or #b0 == 0 then return nil end
  local c0 = string.byte(b0)
  if c0 < 0x80 then return c0
  elseif c0 < 0xC0 then
    local b1 = sock:receive_bytes(1); if not b1 then return nil end
    return ((c0 & 0x3F) << 8) | string.byte(b1)
  end
  local rest = sock:receive_bytes(3); if not rest then return nil end
  local b = {string.byte(rest, 1, 3)}
  return ((c0 & 0x1F) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
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
    local w = sock:receive_bytes(len)
    if not w then return nil end
    words[#words+1] = w
  end
  return words
end

local function try_api(host, port_n, user, pass, use_ssl)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok = use_ssl and sock:connect(host, port_n, "ssl") or sock:connect(host, port_n)
  if not ok then return nil end

  send_sentence(sock, {"/login", "=name=" .. user, "=password=" .. pass})
  local r = read_sentence(sock)
  if not r then sock:close(); return nil end

  if r[1] == "!done" then
    local challenge
    for _, w in ipairs(r) do
      if w:sub(1,5) == "=ret=" then challenge = w:sub(6) end
    end
    if challenge then
      local md5 = require "openssl".md5
      local ch = stdnse.fromhex(challenge)
      local hash = stdnse.tohex(md5("\x00" .. pass .. ch))
      send_sentence(sock, {"/login", "=name=" .. user, "=response=00" .. hash})
      r = read_sentence(sock)
    end
    if r and r[1] == "!done" then
      -- Get version
      local version = "?"
      send_sentence(sock, {"/system/resource/print", "=.proplist=version,board-name"})
      local vr = read_sentence(sock)
      if vr then
        for _, w in ipairs(vr) do
          if w:sub(1,9) == "=version=" then version = w:sub(10) end
        end
        read_sentence(sock)  -- consume !done
      end
      sock:close()
      return version
    end
  end
  sock:close()
  return nil
end

local function try_rest(host, port_n, user, pass)
  local b64 = stdnse.base64_encode(user .. ":" .. pass)
  local resp = http.get(host, port_n, "/rest/system/resource",
    {timeout = 5000, header = {Authorization = "Basic " .. b64}})
  if resp and resp.status == 200 and resp.body then
    local version = resp.body:match('"version":"([^"]+)"') or "?"
    return version
  end
  return nil
end

-- ── Main action ───────────────────────────────────────────────────────────────

action = function(host, port)
  local pn       = port.number
  local use_ssl  = pn == 8729 or pn == 443
  local is_api   = pn == 8728 or pn == 8729
  local is_http  = pn == 80 or pn == 443

  -- Parse extra creds
  local cred_list = {table.unpack(DEFAULT_CREDS)}
  local extra = stdnse.get_script_args("mikrotik-default-creds.extra")
  if extra then
    for pair in extra:gmatch("[^,]+") do
      local u, p = pair:match("^([^:]+):?(.*)")
      if u then cred_list[#cred_list+1] = {u, p or ""} end
    end
  end

  local found = {}

  for _, pair in ipairs(cred_list) do
    local user, pass = pair[1], pair[2]
    local version = nil

    if is_api then
      version = try_api(host, pn, user, pass, use_ssl)
    elseif is_http then
      version = try_rest(host, pn, user, pass)
    end

    if version then
      found[#found+1] = {
        user    = user,
        pass    = pass,
        version = version,
        port    = pn,
      }
      creds.add(host, port, user, pass, creds.State.VALID)
      -- Continue looking for other valid accounts
    end
  end

  if #found == 0 then return "No default credentials found" end

  local output = stdnse.output_table()
  output["CREDENTIALS FOUND"] = #found .. " valid pair(s)"
  for i, f in ipairs(found) do
    local label = i == 1 and "primary" or ("account_" .. i)
    output[label] = string.format(
      "%s:%s — RouterOS %s (port %d)",
      f.user, f.pass == "" and "(empty)" or f.pass, f.version, f.port
    )
  end
  return output
end

