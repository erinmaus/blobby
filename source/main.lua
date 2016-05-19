-- Blobby application implementation.
--
-- This file is licensed under the BSD 2-Clause license.
--
-- Copyright (c) 2016 Aaron Bolyard.
local command = require 'command'
local crypto = require 'crypto'
local database = require 'database'

local _error = error
function error(message)
	_error(message, 0)
end

local function copy_to_clipboard(value)
	local jit = require 'jit'

	if jit.os == 'BSD' then
		local f, e = io.popen("xclip -selection clipboard", "w")

		if not f then
			error(e)
		end

		f:write(value)
		f:close()
	else
		error("unsupported platform; cannot copy to clipboard")
	end
end

local function write(...)
	io.write(string.format(...))
end

local function write_line(...)
	io.write(string.format(...), "\n")
end

local function write_field(obj, field, masked)
	local f

	if masked then
		if obj[field] and obj[field] ~= "" then
			f = "********"
		else
			f = ""
		end
	else
		f = obj[field]
	end

	write_line("%20s: %s", field, f)
end

local function read_line(...)
	write(...)

	return io.read("*l")
end

local function masked_read_line(...)
	local prompt = string.format(...)

	return crypto.read_passphrase(prompt, true)
end

local function require_argument(name, v)
	if not v then
		error(string.format("argument '%s' required", name))
	end
end

local function validate_enum(v, e)
	local match = false
	for i = 1, #e do
		if v == e[i] then
			match = true

			break
		end
	end

	if not match then
		local m = string.format(
			"value '%s' is not valid; must be one of:\n\t%s",
			v,
			table.concat(e, ", "))
		error(m)
	end
end

local function read_new_password()
	while true do
		local a = masked_read_line("Enter password: ", true)
		local b = masked_read_line("Verify password: ", true)

		if a ~= b then
			write_line("Passwords don't match! Try again.")
		else
			return a
		end
	end
end

local Confirm = command.create()
function Confirm.yes()
	return true
end

function Confirm.no()
	return false
end

local function ask_confirmation(message)
	write_line(message)

	local success, result
	while not success do
		local c = read_line("Enter 'yes' to confirm, 'no' to cancel: ")

		success, result = Confirm(c)

		if not success then
			write_line("Invalid option.")
		end
	end

	return result
end

local State = {}
local Session = command.create()
function Session.list(field, pattern)
	field = string.lower(field or 'all')

	validate_enum(field, { 'all', 'domain', 'username', 'category' })

	local success, result = State.database:query_list(field, pattern)
	if not success then
		write_line("Error: %s", result)
	end

	write_line("%20s %20s %20s", "username", "domain", "category")

	local matches = 0
	local entry = result()
	while entry do
		write_line(
			"%20s %20s %20s",
			entry.username,
			entry.domain,
			entry.category)
		matches = matches + 1
		entry = result()
	end

	write_line("\nFound %d matches.", matches)
end

function Session.add(username, domain, category)
	require_argument("username", username)
	require_argument("domain", domain)

	local success, entry = State.database:add_entry(username, domain, category)

	if success then
		State.active = entry
		write_line("Entry successfully created.")
	else
		write_line("Entry already exists in database.")
	end
end

function Session.remove()
	if State.active == nil then
		write_line("No active entry. Select an entry and then try again.")
	else
		local m = string.format(
			"Are you sure you want to remove '%s' from '%s'?",
			State.active.username,
			State.active.domain)

		if ask_confirmation(m) then
			local result = State.database:remove_entry(State.active)

			if not result then
				write_line("Entry was not in database.")
			end

			State.active = nil
		else
			write_line("No action taken.")
		end
	end
end

local function get_active_entry(username, domain, category)
	if username == nil
		and domain == nil
		and category == nil
	then
		if State.active == nil then
			write_line("No active entry.")

			return nil
		end

		return State.active
	end

	local e = State.database:query_single(username, domain, category)
	if e == nil then
		write_line("No entries found matching parameters.")

		return nil
	end

	return e
end

function Session.view(username, domain, category)
	local e = get_active_entry(username, domain, category)

	if e then
		write_field(e, "username")
		write_field(e, "domain")
		write_field(e, "category")
		write_field(e, "password", true)
		write_field(e, "note")

		for key in pairs(e.data) do
			write_line("%q = ********", key)
		end

		State.active = e
	end
end

local Edit = command.create()
function Edit.password(...)
	local e = get_active_entry(...)
	if e then
		write_line("Editing password for '%s' from '%s'.", e.username, e.domain)

		local password = read_new_password()
		if password == "" then
			write_line("No action taken. Password is empty.")
		else
			e.password = password
			write_line("Password successfully changed.")
		end
	end
end

function Edit.data(id, ...)
	require_argument("id", id)

	local e = get_active_entry(...)
	if e then
		write_line("Editing data for '%s' from '%s'.", e.username, e.domain)

		if e.data[id] then
			local m = string.format("Do you want to delete '%s'?", id)

			if ask_confirmation(m) then
				e.data[id] = nil

				return
			end
		end

		local value = masked_read_line("Enter value for '%s': ", id)

		if value == "" then
			write_line("No action taken. Value is empty.")
		else
			e.data[id] = value
			write_line("Data successfully changed.")
		end
	end
end

function Edit.note(...)
	local e = get_active_entry(...)
	if e then
		write_line("Editing note for '%s' from '%s'.", e.username, e.domain)

		if e.note ~= "" then
			write_line("Currently, the note is: '%s'.", e.note)
		end

		e.note = read_line("Enter new note: ")

		write_line("Note successfully changed.")
	end
end

function Session.edit(field, ...)
	require_argument("field", field)
	validate_enum(string.lower(field), { 'password', 'note', 'data' })

	Edit(field, ...)
end

local Fetch = command.create()
function Fetch.password(...)
	local e = get_active_entry(...)
	if e then
		return e, e.password
	end

	return nil, nil
end

function Fetch.data(id, ...)
	require_argument("id", id)

	local e = get_active_entry(...)
	if e then
		if e.data[id] == nil then
			write_line("Data '%s' has no value.", id)

			return nil, nil
		end

		return e, e.data[id]
	end

	return nil, nil
end

function Fetch.note(...)
	local e = get_active_entry(...)
	if e then
		return e, e.note
	end

	return nil, nil
end

function Session.show(field, ...)
	require_argument("field", field)
	validate_enum(string.lower(field), { 'password', 'note', 'data' })

	local success, e, f = Fetch(field, ...)
	if success then
		if e then
			write_line(
				"Showing requested field for '%s' from '%s'.",
				e.username,
				e.domain)
			write_line("Result: %s", f)
		else
			write_line("Nothing to show.")
		end
	end
end

function Session.copy(field, ...)
	require_argument("field", field)
	validate_enum(string.lower(field), { 'password', 'note', 'data' })

	local success, e, f = Fetch(field, ...)
	if success then
		if e then
			copy_to_clipboard(f)

			write_line(
				"Copied requested field for '%s' from '%s'.",
				e.username,
				e.domain)
		else
			write_line("Nothing to copy.")
		end
	end
end

function Session.exit()
	if ask_confirmation("Save any changes?") then
		State.database:save(State.database.path)
	end

	return 'exit'
end

local Main = command.create()
function Main.create(path)
	require_argument("path", path)
	write_line("Creating new password database.")

	local passphrase
	repeat
		local a = crypto.read_passphrase("Enter passphrase: ")
		local b = crypto.read_passphrase("Verify passphrase: ")

		if crypto.compare_passphrases(a, b) then
			passphrase = a
			crypto.free_passphrase(b)
		else
			write_line("Passphrases don't match! Try again.")
			crypto.free_passphrase(a)
			crypto.free_passphrase(b)
		end
	until passphrase ~= nil

	local d = database.create(passphrase)
	d:save(path)

	crypto.free_passphrase(passphrase)
	d:destroy()

	return false, string.format("Success! Created database '%s'.", path)
end

function Main.open(path)
	require_argument("path", path)

	local passphrase = crypto.read_passphrase("Enter passphrase: ")
	local success, d = database.load(path, passphrase)

	if not success then
		return false, "Unable to open database. Wrong passphrase?"
	else
		write_line("Successfully opened '%s'.", path)
	end

	crypto.free_passphrase(passphrase)

	return true, d
end

function Main.help()
	write_line("blobby <open/create/help> [path]")
	write_line("\topen\t\tdecrypt database at 'path' and begin session")
	write_line("\tcreate\t\tcreate database at 'path'")
	write_line("\thelp\t\tthis message")

	return false, nil
end

local function session_loop(d, path)
	State.database = d

	local is_running = true
	while is_running do
		local c = read_line("> ")

		local success, result = Session(command.parse_arguments(c))
		if not success then
			write_line("Error: %s", result)
		end

		if result == 'exit' then
			is_running = false
		end
	end

	State.database:destroy()
end

local function start(...)
	if select("#", ...) == 0 then
		Main("help")

		return
	end

	local success, a, b = Main(...)

	if not success then
		write_line("Error: %s", a)
		write_line("Run 'blobby help' for a list of valid commands.")

		os.exit(1)
	end

	if a then
		session_loop(b)
	else
		if b then
			write_line(b)
		end
	end
end

start(...)
