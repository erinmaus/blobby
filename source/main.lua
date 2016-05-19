-- Commands interface. A simple way to handle dispatching commands and parse
-- arguments.
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
	end

	return true, d
end

function Main.help()
	write_line("blobby <open/create/help> [path]")
	write_line("\topen\t\tdecrypt database at 'path' and begin session")
	write_line("\tcreate\t\tcreate database at 'path'")
	write_line("\thelp\t\tthis message")

	return false, nil
end

local function session_loop()
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
