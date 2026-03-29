local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Connects to the MikroTik RouterOS binary API (TCP/8728 or TCP/8729),
authenticates with provided credentials, and retrieves system information.

Key fix: Nmap socket receive_bytes(n) returns (status_bool, data_string)
AND may return more than n bytes. We receive all data at once and parse
the RouterOS binary protocol entirely in-memory (no per-byte socket reads).
]]

---
-- @usage
--   nmap -p 8728 -sT -Pn --script mikrotik-api-info --script-args "mikrotik-api-info.user=admin,mikrotik-api-info.pass=pass" <target>
--
-- @output
-- | mikrotik-api-info:
-- |   version: 7.20.7 (long-term)
-- |   board: CHR DigitalOcean Droplet
-- |   cpu-load: 1%
-- |_  firewall-rules: 0 -- WARNING: NO FIREWALL RULES

author = "Andre Henrique <@mrhenrike>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

portrule = shortport.port_or_service({8728, 8729}, {"routeros-api", "mikrotik-api"})

-- ── RouterOS binary protocol — in-memory parser ──────────────────────────────

local function enc_len(n)
  if n < 0x80 then return string.char(n) end
  if n < 0x4000 then n = n | 0x8000; return string.char((n>>8)&0xFF, n&0xFF) end
  n = n | 0xC00000; return string.char((n>>16)&0xFF,(n>>8)&0xFF,n&0xFF)
end

-- Build binary RouterOS sentence
local function make_pkt(words)
  local t = {}
  for _, w in ipairs(words) do t[#t+1] = enc_len(#w) .. w end
  t[#t+1] = "\x00"
  return table.concat(t)
end

-- Parse RouterOS binary buffer into list of sentences
-- Each sentence is a list of word strings; sentences separated by empty-word (0x00)
local function parse_buf(buf)
  local sentences = {}
  local words = {}
  local pos = 1
  local buflen = #buf

  while pos <= buflen do
    local c0 = string.byte(buf, pos)
    local len, skip
    if c0 < 0x80 then
      len = c0; skip = 1
    elseif c0 < 0xC0 then
      if pos + 1 > buflen then break end
      len = ((c0 & 0x3F) << 8) | string.byte(buf, pos+1); skip = 2
    else
      if pos + 3 > buflen then break end
      local b1,b2,b3 = string.byte(buf, pos+1, pos+3)
      len = ((c0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3; skip = 4
    end
    pos = pos + skip

    if len == 0 then
      -- End of sentence
      sentences[#sentences+1] = words
      words = {}
    else
      if pos + len - 1 > buflen then break end  -- incomplete
      local word = string.sub(buf, pos, pos + len - 1)
      words[#words+1] = word
      pos = pos + len
    end
  end
  -- Flush remaining words
  if #words > 0 then sentences[#sentences+1] = words end
  return sentences
end

-- Send words and get response parsed into sentences
local function api_call(sock, words)
  local pkt = make_pkt(words)
  local ok, err = sock:send(pkt)
  if not ok then return nil, "send: "..(err or "?") end

  -- Collect all response data (receive_bytes returns (status, data))
  local buf = ""
  local deadline = nmap.clock_ms() + 8000
  while nmap.clock_ms() < deadline do
    local status, chunk = sock:receive_bytes(4096)
    if status and chunk and type(chunk) == "string" and #chunk > 0 then
      buf = buf .. chunk
      -- Check if we have !done or !trap in current buffer
      if buf:find("\x05!done") or buf:find("\x05!trap") or buf:find("\x06!fatal") then
        -- Wait briefly for any trailing data
        stdnse.sleep(0.05)
        local s2, c2 = sock:receive_bytes(1024)
        if s2 and c2 and #c2 > 0 then buf = buf .. c2 end
        break
      end
    else
      stdnse.sleep(0.05)
    end
  end

  return parse_buf(buf)
end

-- Extract key=value pairs from a sentence
local function props_from_sentence(sentence)
  local p = {}
  for _, w in ipairs(sentence) do
    if w:sub(1,1) == "=" then
      local k, v = w:match("^=([^=]+)=(.*)")
      if k then p[k] = v end
    end
  end
  return p
end

-- Get all !re rows as list of prop tables
local function get_rows(sentences)
  local rows = {}
  for _, sent in ipairs(sentences) do
    if sent[1] == "!re" then
      rows[#rows+1] = props_from_sentence(sent)
    end
  end
  return rows
end

-- ── Authentication ────────────────────────────────────────────────────────────

local function login(sock, user, pass)
  -- RouterOS 7.x: single-round plaintext
  local sentences, err = api_call(sock, {"/login", "=name="..user, "=password="..pass})
  if not sentences then return false, "no response: "..(err or "?") end

  -- Check response
  for _, sent in ipairs(sentences) do
    if sent[1] == "!done" then
      -- Check for 6.x challenge
      local challenge
      for _, w in ipairs(sent) do
        if w:sub(1,5) == "=ret=" then challenge = w:sub(6) end
      end
      if challenge then
        -- 6.x MD5
        local ok2, openssl = pcall(require, "openssl")
        if not ok2 then return false, "6.x auth requires OpenSSL. Use Python tool instead." end
        local ok3, digest = pcall(openssl.md5, "\x00"..pass..stdnse.fromhex(challenge))
        if not ok3 then return false, "OpenSSL MD5 unavailable on this Nmap build" end
        sentences, err = api_call(sock, {"/login","=name="..user,"=response=00"..stdnse.tohex(digest)})
        if not sentences then return false, "no response to 6.x auth" end
        for _, s in ipairs(sentences) do
          if s[1] == "!done" then return true end
        end
        return false, "6.x auth rejected"
      end
      return true  -- 7.x success
    elseif sent[1] == "!trap" then
      local msg = "invalid credentials"
      for _, w in ipairs(sent) do
        if w:sub(1,9) == "=message=" then msg = w:sub(10) end
      end
      return false, msg
    end
  end
  return false, "unexpected response"
end

-- ── Main ──────────────────────────────────────────────────────────────────────

action = function(host, port)
  local user = stdnse.get_script_args("mikrotik-api-info.user") or "admin"
  local pass = stdnse.get_script_args("mikrotik-api-info.pass") or ""

  local sock = nmap.new_socket()
  sock:set_timeout(10000)

  if not sock:connect(host, port) then return "Connect failed" end

  local authed, auth_err = login(sock, user, pass)
  if not authed then
    sock:close()
    return "Auth failed ("..user.."): "..(auth_err or "?")
  end

  local output = stdnse.output_table()

  -- System resource
  local s = api_call(sock, {"/system/resource/print"})
  if s then
    local rows = get_rows(s)
    if rows[1] then
      local p = rows[1]
      output["version"]      = p["version"] or "?"
      output["board"]        = p["board-name"] or "?"
      output["architecture"] = p["architecture-name"] or "?"
      output["cpu-load"]     = (p["cpu-load"] or "?") .. "%"
      output["uptime"]       = p["uptime"] or "?"
      local fm = math.floor((tonumber(p["free-memory"] or 0))/1048576)
      local tm = math.floor((tonumber(p["total-memory"] or 0))/1048576)
      output["memory"]       = fm .. " MB free / " .. tm .. " MB total"
    end
  end

  -- Users
  s = api_call(sock, {"/user/print"})
  if s then
    local users = {}
    for _, p in ipairs(get_rows(s)) do
      if p["name"] then users[#users+1] = p["name"].." (group="..(p["group"] or "?")..")" end
    end
    if #users > 0 then output["users"] = table.concat(users, ", ") end
  end

  -- IP Services
  s = api_call(sock, {"/ip/service/print"})
  if s then
    local seen, svcs = {}, {}
    for _, p in ipairs(get_rows(s)) do
      if p["name"] and p["disabled"] ~= "true" then
        local entry = p["name"]..":" ..(p["port"] or "?")
        if not seen[entry] then seen[entry]=true; svcs[#svcs+1]=entry end
      end
    end
    if #svcs > 0 then output["services"] = table.concat(svcs, ", ") end
  end

  -- Firewall count
  s = api_call(sock, {"/ip/firewall/filter/print"})
  local fw = s and #get_rows(s) or 0
  output["firewall-rules"] = fw .. " rule(s)"
  if fw == 0 then
    output["firewall-rules"] = "0 -- WARNING: NO FIREWALL RULES (all mgmt ports exposed!)"
  end

  sock:close()
  return output
end
