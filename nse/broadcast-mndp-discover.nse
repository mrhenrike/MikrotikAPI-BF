local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovers MikroTik devices on the local network segment using the
MikroTik Neighbor Discovery Protocol (MNDP) broadcast on UDP port 5678.

MNDP is used by Winbox and other MikroTik tools to discover devices on
the local Layer-2 segment. The protocol sends a UDP broadcast and
devices respond with their MAC address, IP address, identity, RouterOS
version, board name, and software ID.

This script sends an MNDP broadcast request and collects responses.
Only devices on the same broadcast domain will respond.

References:
  - https://wiki.mikrotik.com/wiki/MNDP
  - https://github.com/mrhenrike/MikrotikAPI-BF (modules/mac_server.py)
]]

---
-- @usage
--   nmap --script broadcast-mndp-discover
--   nmap --script broadcast-mndp-discover --script-args broadcast-mndp-discover.timeout=5
--
-- @output
-- Pre-scan script results:
-- | broadcast-mndp-discover:
-- |   192.168.1.1
-- |     identity: MikroTik
-- |     version: 7.20.7 (long-term)
-- |     board: RB750Gr3
-- |     mac: AA:BB:CC:DD:EE:FF
-- |_  Use --script-args broadcast-mndp-discover.timeout=N to wait longer.
--
-- @args broadcast-mndp-discover.timeout  Seconds to wait for responses (default: 3)
-- @args broadcast-mndp-discover.port     UDP port to broadcast on (default: 5678)

author = "Andre Henrique <@mrhenrike>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe", "discovery"}

prerule = function()
  return nmap.address_family() == "inet"
end

-- MNDP TLV type IDs
local TLV_MAC      = 0x0001
local TLV_IDENTITY = 0x0005
local TLV_VERSION  = 0x0007
local TLV_PLATFORM = 0x000A
local TLV_BOARD    = 0x000D
local TLV_IPV4     = 0x0011

local function parse_tlv(data)
  local result = {}
  local pos = 5  -- skip 4-byte MNDP header (version, ttl, seqno)
  while pos + 4 < #data do
    local tlv_type = string.unpack("<I2", data, pos)
    local tlv_len  = string.unpack("<I2", data, pos + 2)
    pos = pos + 4
    if tlv_len == 0 then break end
    local value = string.sub(data, pos, pos + tlv_len - 1)
    pos = pos + tlv_len

    if tlv_type == TLV_MAC and tlv_len == 6 then
      result.mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
        string.byte(value, 1, 6))
    elseif tlv_type == TLV_IDENTITY then
      result.identity = value
    elseif tlv_type == TLV_VERSION then
      result.version = value
    elseif tlv_type == TLV_PLATFORM then
      result.platform = value
    elseif tlv_type == TLV_BOARD then
      result.board = value
    elseif tlv_type == TLV_IPV4 and tlv_len == 4 then
      local b = {string.byte(value, 1, 4)}
      result.ip = string.format("%d.%d.%d.%d", b[1], b[2], b[3], b[4])
    end
  end
  return result
end

action = function()
  local timeout = tonumber(stdnse.get_script_args("broadcast-mndp-discover.timeout")) or 3
  local port    = tonumber(stdnse.get_script_args("broadcast-mndp-discover.port"))    or 5678

  -- MNDP discovery probe: 4-byte header (version=0, ttl=0, seqno=0)
  local probe = "\x00\x00\x00\x00"

  local sock = nmap.new_socket("udp")
  sock:set_timeout(timeout * 1000)

  local status, err = sock:sendto("255.255.255.255", port, probe)
  if not status then
    return "Could not send MNDP broadcast: " .. (err or "?")
  end

  local devices = {}
  local seen    = {}
  local deadline = nmap.clock_ms() + (timeout * 1000)

  while nmap.clock_ms() < deadline do
    local data, addr = sock:receive()
    if not data then break end
    if not seen[addr] then
      seen[addr] = true
      local dev = parse_tlv(data)
      dev.src_ip = addr
      table.insert(devices, dev)
    end
  end
  sock:close()

  if #devices == 0 then
    return "No MikroTik devices found on this segment (L2 boundary required)"
  end

  local output = stdnse.output_table()
  for _, dev in ipairs(devices) do
    local ip_key = dev.ip or dev.src_ip or "?"
    output[ip_key] = stdnse.output_table()
    if dev.identity then output[ip_key]["identity"] = dev.identity end
    if dev.version  then output[ip_key]["version"]  = dev.version  end
    if dev.board    then output[ip_key]["board"]    = dev.board    end
    if dev.mac      then output[ip_key]["mac"]      = dev.mac      end
    if dev.platform then output[ip_key]["platform"] = dev.platform end
  end
  output["_note"] = string.format(
    "%d device(s) found. Use --script-args broadcast-mndp-discover.timeout=N to wait longer.",
    #devices)
  return output
end
