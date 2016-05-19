-- Blobby application implementation.
--
-- This file is licensed under the BSD 2-Clause license.
--
-- Copyright (c) 2016 Aaron Bolyard.
local command = require 'command'
local crypto = require 'crypto'
local database = require 'database'

local function write(...)
	io.write(string.format(...))
end

local function write_line(...)
	io.write(string.format(...), "\n")
end

local function read_line(...)
	write(...)

	return io.read("*l")
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

local Confirm = command.create()
function Confirm.yes()
	return true
end

function Confirm.no()
	return false
end

function ask_confirmation(message)
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
	field = field or 'all'

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

function Session.exit()
	if ask_confirmation("Save any changes?") then
		State.database:save(State.database.path)
	end

	return 'exit'
end

local Main = command.create()
function Main.create(path)
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
	local success, a, b = Main(...)

	if not success then
		io.stderr:write(a)

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
