local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local lfs = require("libs/libkoreader-lfs")
local _ = require("gettext")

local source = debug.getinfo(1, "S").source:sub(2)
local plugin_dir = source:match("(.+)/main.lua$") or "."
if plugin_dir:sub(1, 1) ~= "/" then
    -- KOReader commonly loads external plugins as
    -- @plugins/name.koplugin/main.lua. Resolve that path once, before the
    -- launcher changes its working directory, otherwise the relative prefix
    -- is applied twice (plugins/name/plugins/name/bin/...).
    plugin_dir = lfs.currentdir() .. "/" .. plugin_dir
end

local function shell_quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function read_file(path)
    local file = io.open(path, "r")
    if not file then return nil end
    local value = file:read("*a")
    file:close()
    return value
end

local function read_tail(path, max_bytes)
    local file = io.open(path, "r")
    if not file then return "" end
    local size = file:seek("end") or 0
    local start = math.max(0, size - max_bytes)
    file:seek("set", start)
    local value = file:read("*a") or ""
    file:close()
    if start > 0 then
        value = value:gsub("^[^\n]*\n?", "", 1)
        value = "…\n" .. value
    end
    return value
end

local function command_succeeded(result)
    return result == true or result == 0
end

local function write_file(path, value, mode)
    local file, err = io.open(path, "w")
    if not file then return nil, err end
    file:write(value)
    file:close()
    if mode then os.execute("chmod " .. mode .. " " .. shell_quote(path) .. " 2>/dev/null") end
    return true
end

local function write_file_atomic(path, value, mode)
    local temporary = path .. ".tmp"
    local ok, err = write_file(temporary, value, mode)
    if not ok then return nil, err end
    if not os.rename(temporary, path) then
        os.remove(temporary)
        return nil, "cannot replace " .. path
    end
    return true
end

local function plausible_client_data(encoded)
    if encoded == "" then return true end
    -- atrust.ClientAuthData is emitted by json.Marshal as an object beginning
    -- with {"cookies"..., whose standard Base64 representation starts eyJ.
    return encoded:match("^eyJ") ~= nil
end

local function json_escape(value)
    value = tostring(value or "")
    local output = {'"'}
    local replacements = {
        [8] = "\\b", [9] = "\\t", [10] = "\\n",
        [12] = "\\f", [13] = "\\r", [34] = "\\\"", [92] = "\\\\",
    }
    for index = 1, #value do
        local byte = value:byte(index)
        if replacements[byte] then
            output[#output + 1] = replacements[byte]
        elseif byte < 32 then
            output[#output + 1] = string.format("\\u%04x", byte)
        else
            -- UTF-8 bytes are copied unchanged; JSON strings are UTF-8.
            output[#output + 1] = value:sub(index, index)
        end
    end
    output[#output + 1] = '"'
    return table.concat(output)
end

local function json_bool(value)
    return value and "true" or "false"
end

local function json_number(value, default)
    value = tonumber(value)
    if not value then value = default end
    return tostring(value)
end

local function json_object(values)
    local output = {}
    for _, item in ipairs(values) do
        local key, value = item[1], item[2]
        if value ~= nil then
            output[#output + 1] = json_escape(key) .. ":" .. value
        end
    end
    return "{" .. table.concat(output, ",") .. "}"
end

-- Decode only JSON strings/numbers needed from the Go bridge. Keeping this
-- small avoids depending on a particular KOReader JSON implementation.
local function json_string_field(line, key)
    local start = line:find('"' .. key .. '"', 1, true)
    if not start then return nil end
    local colon = line:find(":", start + #key + 2, true)
    if not colon then return nil end
    local quote = line:find('"', colon + 1, true)
    if not quote then return nil end
    local out, escaped = {}, false
    for index = quote + 1, #line do
        local char = line:sub(index, index)
        if escaped then
            local replacements = { ["n"] = "\n", ["r"] = "\r", ["t"] = "\t", ["b"] = "\b", ["f"] = "\f", ["\\"] = "\\", ["\""] = '"', ["/"] = "/" }
            out[#out + 1] = replacements[char] or char
            escaped = false
        elseif char == "\\" then
            escaped = true
        elseif char == '"' then
            return table.concat(out)
        else
            out[#out + 1] = char
        end
    end
    return nil
end

local HITSZConnect = WidgetContainer:extend{
    name = "hitsz_connect",
    is_doc_only = false,
    running = false,
    event_offset = 0,
    request_id = "koreader",
}

function HITSZConnect:init()
    self.config_path = plugin_dir .. "/config.lua"
    self.state_dir = plugin_dir .. "/state"
    -- Kindle's /mnt/us filesystem does not support named pipes. Runtime IPC
    -- belongs in /tmp; it also keeps MFA commands out of exported state logs.
    self.command_fifo = "/tmp/hitsz-connect-commands.fifo"
    self.event_file = self.state_dir .. "/events.ndjson"
    self.log_file = self.state_dir .. "/connect.log"
    self.pid_file = self.state_dir .. "/connect.pid"
    self.client_data_file = self.state_dir .. "/client_data.b64"
    self.plugin_log_file = self.state_dir .. "/plugin.log"
    self.launcher_log_file = self.state_dir .. "/launcher.log"
    -- Keep the one-shot start request out of state/: it contains credentials
    -- and must not be accidentally included when diagnostics are exported.
    self.start_command_file = "/tmp/hitsz-connect-start.json"
    self.poll_task = function()
        self:runSafely("pollEvents", function() self:pollEvents() end)
    end
    self:ensureStateDir()
    self:refreshRunning()
    if self.ui and self.ui.menu then
        self.ui.menu:registerToMainMenu(self)
    end
end

function HITSZConnect:runSafely(action, callback)
    local ok, err = xpcall(callback, debug.traceback)
    if ok then return true end
    local message = "HITSZ aTrust plugin " .. tostring(action) .. " failed:\n" .. tostring(err)
    write_file(self.plugin_log_file, message .. "\n", "600")
    pcall(function() self:showMessage(message, 15) end)
    return false
end

function HITSZConnect:ensureStateDir()
    os.execute("mkdir -p " .. shell_quote(self.state_dir) .. " 2>/dev/null")
    os.execute("chmod 700 " .. shell_quote(self.state_dir) .. " 2>/dev/null")
end

function HITSZConnect:loadConfig()
    local ok, config = pcall(dofile, self.config_path)
    if not ok or type(config) ~= "table" then
        return nil, _("Cannot read config.lua. Edit it on your computer before copying the plugin to Kindle.")
    end
    local method = tostring(config.mfa_method or ""):lower()
    if config.profile ~= nil and tostring(config.profile):lower() ~= "hitsz" then
        return nil, _("config.lua must use profile = 'hitsz'.")
    end
    if not config.username or config.username == "" or tostring(config.username):match("^REPLACE_") then
        return nil, _("Set username in config.lua before connecting.")
    end
    if not config.password or config.password == "" or tostring(config.password):match("^REPLACE_") then
        return nil, _("Set password in config.lua before connecting.")
    end
    if method ~= "app" and method ~= "sms" and method ~= "otp" then
        return nil, _("mfa_method must be app, sms, or otp in config.lua.")
    end
    if method == "otp" and (not config.mfa_otp_secret or config.mfa_otp_secret == "") then
        return nil, _("Set mfa_otp_secret for OTP MFA in config.lua.")
    end
    config.profile = "hitsz"
    config.server_address = config.server_address or "trust.hitsz.edu.cn"
    config.server_port = tonumber(config.server_port) or 443
    config.mfa_method = method
    config.socks_bind = config.socks_bind or "127.0.0.1:1080"
    config.http_bind = config.http_bind or "127.0.0.1:1081"
    config.dns_relay_bind = config.dns_relay_bind or "127.0.0.1:53535"
    config.hitsz_dns_server = config.hitsz_dns_server or "10.248.98.30"
    if config.ca_cert_file and config.ca_cert_file ~= "" then
        local cert = io.open(config.ca_cert_file, "r")
        if not cert then return nil, _("ca_cert_file does not exist: ") .. tostring(config.ca_cert_file) end
        cert:close()
    end
    return config
end

function HITSZConnect:binaryPath()
    local arch = jit and jit.arch or ""
    if arch == "" then
        local arch_pipe = io.popen("uname -m 2>/dev/null", "r")
        arch = arch_pipe and arch_pipe:read("*l") or ""
        if arch_pipe then arch_pipe:close() end
    end
    local name
    if arch == "aarch64" or arch == "arm64" then
        name = "hitsz-connect-linux-arm64"
    elseif arch == "armv7l" or arch == "armv6l" or arch == "arm" then
        name = "hitsz-connect-linux-arm"
    else
        return nil, _("This KOReader package contains Kindle ARM binaries only.")
    end
    local path = plugin_dir .. "/bin/" .. name
    local probe = io.open(path, "r")
    if not probe then return nil, _("Missing bundled aTrust binary: ") .. name end
    probe:close()
    return path
end

function HITSZConnect:readPID()
    local pid = tonumber((read_file(self.pid_file) or ""):match("%d+"))
    if pid then
        local cmdline = read_file("/proc/" .. pid .. "/cmdline") or ""
        if cmdline:find("hitsz%-connect", 1) then
            return pid
        end
    end
    return nil
end

function HITSZConnect:refreshRunning()
    self.pid = self:readPID()
    self.running = self.pid ~= nil
    return self.running
end

function HITSZConnect:send(command)
    local file, err = io.open(self.command_fifo, "w")
    if not file then return nil, err end
    file:write(command, "\n")
    file:close()
    return true
end

function HITSZConnect:buildStart(config)
    local client_data = (read_file(self.client_data_file) or ""):gsub("%s+", "")
    if not plausible_client_data(client_data) then
        os.remove(self.client_data_file)
        client_data = ""
        self.client_data_was_reset = true
    end
    self.used_client_data = client_data ~= ""
    local values = {
        {"profile", json_escape("hitsz")},
        {"protocol", json_escape("atrust")},
        {"server_address", json_escape(config.server_address)},
        {"server_port", json_number(config.server_port, 443)},
        {"username", json_escape(config.username)},
        {"password", json_escape(config.password)},
        {"mfa_method", json_escape(config.mfa_method)},
        {"mfa_otp_secret", json_escape(config.mfa_otp_secret or "")},
        {"socks_bind", json_escape(config.socks_bind)},
        {"http_bind", json_escape(config.http_bind)},
        {"dns_relay_bind", json_escape(config.dns_relay_bind)},
        {"hitsz_dns_server", json_escape(config.hitsz_dns_server)},
        {"remember_sso", json_bool(config.remember_sso ~= false)},
        {"remember_mfa", json_bool(config.remember_mfa ~= false)},
        {"update_best_nodes_interval", json_number(config.update_best_nodes_interval, 300)},
        {"no_system_dns_mutation", "true"},
        {"shadowrocket", json_escape("off")},
    }
    local object = json_object(values)
    local tail = ',"clientData":' .. json_escape(client_data)
    return '{"type":"start","requestId":' .. json_escape(self.request_id) .. ',"config":' .. object .. tail .. '}'
end

function HITSZConnect:start()
    if self:refreshRunning() then
        self:showMessage(_("HITSZ aTrust is already running."), 3)
        return
    end
    local config, err = self:loadConfig()
    if not config then self:showMessage(err, 8); return end
    local binary, binary_err = self:binaryPath()
    if not binary then self:showMessage(binary_err, 8); return end
    self:ensureStateDir()
    os.execute("rm -f " .. shell_quote(self.command_fifo) .. " " .. shell_quote(self.event_file) .. " " .. shell_quote(self.log_file) .. " " .. shell_quote(self.launcher_log_file) .. " 2>/dev/null")
    local fifo_result = os.execute("mkfifo " .. shell_quote(self.command_fifo) .. " 2>/dev/null")
    if not command_succeeded(fifo_result) then
        self:showMessage(_("Cannot create control FIFO in /tmp."), 10)
        return
    end
    os.execute("chmod 600 " .. shell_quote(self.command_fifo) .. " 2>/dev/null")
    write_file(self.event_file, "", "600")
    write_file(self.log_file, "", "600")
    write_file(self.launcher_log_file, "", "600")
    os.execute("chmod 700 " .. shell_quote(binary) .. " 2>/dev/null")
    local command = self:buildStart(config)
    local wrote, write_err = write_file(self.start_command_file, command .. "\n", "600")
    if not wrote then
        self:showMessage(_("Cannot write aTrust start request: ") .. tostring(write_err), 8)
        return
    end
    local cert_env = ""
    if config.ca_cert_file and config.ca_cert_file ~= "" then
        cert_env = "SSL_CERT_FILE=" .. shell_quote(config.ca_cert_file) .. " "
    end
    -- Feed the initial command and subsequent FIFO commands through a real
    -- pipe. The fd 3<>FIFO approach is unreliable on Kindle's BusyBox shell:
    -- the Go scanner may see EOF while the command remains in the FIFO.
    local launch = "cd " .. shell_quote(plugin_dir)
        .. "; echo 'HITSZ launcher diagnostic'"
        .. "; echo 'Plugin dir: " .. plugin_dir .. "'"
        .. "; uname -a"
        .. "; echo 'LuaJIT arch: " .. tostring(jit and jit.arch or "unknown") .. "'"
        .. "; ls -l " .. shell_quote(binary)
        .. "; " .. shell_quote(binary) .. " -version"
        .. "; probe_status=$?"
        .. "; echo \"Core probe exit: $probe_status\""
        .. "; if [ \"$probe_status\" -ne 0 ]; then exit \"$probe_status\"; fi"
        .. "; ( cat " .. shell_quote(self.start_command_file)
        .. "; rm -f " .. shell_quote(self.start_command_file)
        .. "; while :; do cat " .. shell_quote(self.command_fifo) .. " || sleep 1; done )"
        .. " | " .. cert_env .. "exec " .. shell_quote(binary)
        .. " -app-bridge >>" .. shell_quote(self.event_file)
        .. " 2>>" .. shell_quote(self.log_file)
        .. " & echo $! >" .. shell_quote(self.pid_file)
        .. "; wait $!"
    os.execute("sh -c " .. shell_quote(launch) .. " >>" .. shell_quote(self.launcher_log_file) .. " 2>&1 &")
    self.event_offset = 0
    self.active_config = config
    self.last_error_message = nil
    self.starting = true
    self.connected = false
    self.success_notified = false
    self.startup_poll_deadline = os.time() + 45
    self.running = true
    self:showMessage(_("Starting HITSZ aTrust…"), 3)
    UIManager:scheduleIn(0.5, self.poll_task)
    local startupCheck
    startupCheck = function()
        self:runSafely("startupCheck", function()
            os.remove(self.start_command_file)
            self:refreshRunning()
            if self.starting and os.time() < (self.startup_poll_deadline or 0) then
                -- Authentication can take longer than five seconds on a
                -- Kindle. Do not call that a failed launch while the bridge
                -- is still expected to emit ready.
                UIManager:scheduleIn(5, startupCheck)
                return
            end
            self.starting = false
            if not self.running and not self.last_error_message and not self.connected then
                local launcher_log = read_tail(self.launcher_log_file, 1200)
                local core_log = read_tail(self.log_file, 1800)
                local log = launcher_log .. (core_log ~= "" and "\nCore:\n" .. core_log or "")
                if log == "" then log = _("No launcher or core log was produced.") end
                if #log > 5000 then log = log:sub(-5000) end
                self:showMessage(_("HITSZ aTrust core could not start.\n\n") .. log, 30)
            end
        end)
    end
    UIManager:scheduleIn(5, startupCheck)
end

function HITSZConnect:stop()
    if not self:refreshRunning() then
        self:showMessage(_("HITSZ aTrust is not running."), 3)
        return
    end
    local pid = self.pid
    self.starting = false
    local sent = self:send('{"type":"stop","requestId":' .. json_escape(self.request_id) .. '}')
    if not sent then os.execute("kill -TERM " .. tostring(pid) .. " 2>/dev/null") end
    self:showMessage(_("Stopping HITSZ aTrust…"), 3)
    UIManager:scheduleIn(2, function()
        if self:readPID() == pid then os.execute("kill -TERM " .. tostring(pid) .. " 2>/dev/null") end
        self:pollEvents()
    end)
end

function HITSZConnect:showMessage(text, timeout)
    UIManager:show(InfoMessage:new{ text = text, timeout = timeout or 5 })
end

function HITSZConnect:showCodeDialog(method)
    if self.code_dialog then UIManager:close(self.code_dialog) end
    self.code_dialog = InputDialog:new{
        title = _("HITSZ ") .. method:upper() .. _(" verification code"),
        input = "",
        input_type = "number",
        buttons = {{
            { text = _("Cancel"), id = "close", callback = function()
                UIManager:close(self.code_dialog)
                self.code_dialog = nil
            end },
            { text = _("Send"), is_enter_default = true, callback = function()
                local code = self.code_dialog:getInputText():match("^%s*(.-)%s*$")
                if code == "" then return end
                UIManager:close(self.code_dialog)
                self.code_dialog = nil
                local ok, err = self:send('{"type":"mfaCode","requestId":' .. json_escape(self.request_id) .. ',"code":' .. json_escape(code) .. '}')
                if not ok then self:showMessage(_("Cannot send MFA code: ") .. tostring(err), 8) end
            end },
        }},
    }
    UIManager:show(self.code_dialog)
    self.code_dialog:onShowKeyboard()
end

function HITSZConnect:pollEvents()
    local file = io.open(self.event_file, "r")
    if file then
        file:seek("set", self.event_offset)
        while true do
            local line = file:read("*l")
            if not line then break end
            self.event_offset = file:seek()
            local event_type = json_string_field(line, "type")
            local state = json_string_field(line, "state")
            local message = json_string_field(line, "message") or json_string_field(line, "error")
            if event_type == "mfaRequired" then
                self:showCodeDialog(json_string_field(line, "method") or "MFA")
            elseif event_type == "clientData" then
                local data = json_string_field(line, "clientData")
                if data and plausible_client_data(data) then
                    write_file_atomic(self.client_data_file, data, "600")
                end
            elseif event_type == "ready" or (event_type == "status" and state == "connected") then
                self.starting = false
                self.connected = true
                if not self.success_notified then
                    self.success_notified = true
                    self:showMessage("连接成功，请设置HTTP代理为http://127.0.0.1:1081", 10)
                end
            elseif event_type == "error" then
                self.starting = false
                self.connected = false
                if self.used_client_data and message and message:find("invalid character", 1, true) then
                    os.remove(self.client_data_file)
                    self.used_client_data = false
                    message = _("Saved aTrust session was invalid and has been cleared. Select Connect again.")
                end
                self.last_error_message = message or _("HITSZ aTrust connection failed.")
                self:showMessage(message or _("HITSZ aTrust connection failed."), 10)
            elseif event_type == "stopped" then
                self.starting = false
                self.connected = false
                self.running = false
            end
        end
        file:close()
    end
    self:refreshRunning()
    if self.starting and os.time() >= (self.startup_poll_deadline or 0) then
        self.starting = false
    end
    -- BusyBox may briefly expose the PID of the pipeline wrapper rather than
    -- the Go process. Keep polling throughout startup so the ready event is
    -- shown when it is emitted, instead of being discovered by Disconnect.
    if self.running or self.starting then UIManager:scheduleIn(1, self.poll_task) end
end

function HITSZConnect:status()
    self:refreshRunning()
    local log = read_tail(self.log_file, 1200)
    local text = self.running and _("HITSZ aTrust process is running.") or _("HITSZ aTrust process is stopped.")
    if log ~= "" then text = text .. "\n\n" .. log end
    local plugin_log = read_tail(self.plugin_log_file, 700)
    if plugin_log ~= "" then text = text .. "\n\nPlugin:\n" .. plugin_log end
    local launcher_log = read_tail(self.launcher_log_file, 700)
    if launcher_log ~= "" then text = text .. "\n\nLauncher:\n" .. launcher_log end
    self:showMessage(text, 15)
end

function HITSZConnect:addToMainMenu(menu_items)
    menu_items.hitsz_connect = {
        text = _("HITSZ aTrust"),
        -- Both ReaderMenu and FileManagerMenu expose their Settings > Network
        -- submenu with the "network" sorting hint. Without this, an external
        -- plugin item is left outside the known menu order and may be hidden.
        sorting_hint = "network",
        checked_func = function() return self:refreshRunning() end,
        sub_item_table = {
            { text = _("Connect"), enabled_func = function() return not self:refreshRunning() end, callback = function()
                self:runSafely("start", function() self:start() end)
            end },
            { text = _("Disconnect"), enabled_func = function() return self:refreshRunning() end, callback = function()
                self:runSafely("stop", function() self:stop() end)
            end },
            { text = _("Status / log"), keep_menu_open = true, callback = function()
                self:runSafely("status", function() self:status() end)
            end },
        },
    }
end

function HITSZConnect:stopPlugin()
    if self:refreshRunning() then self:stop() end
end

function HITSZConnect:onCloseWidget()
    UIManager:unschedule(self.poll_task)
    local pid = self:readPID()
    if pid then
        -- KOReader is closing, so do not rely on a future UI callback for the
        -- fallback. SIGTERM invokes the Go core's registered cleanup hooks.
        os.execute("kill -TERM " .. tostring(pid) .. " 2>/dev/null")
    end
end

return HITSZConnect
