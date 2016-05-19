-- Interface for password database. Provides methods for saving/loading,
-- valdiating, querying, adding/editing entries, and other such database things.
--
-- This file is licensed under the BSD 2-Clause license.
--
-- Copyright (c) 2016 Aaron Bolyard.
local crypto = require 'crypto'
local serpent = require 'serpent'

local O = {}

-- Saves the database to a file at 'path'.
--
-- The database will be encrypted. A public section of the database contains
-- the necessary data to regenerate the key with the correct passphrase and
-- deserialize the private section.
function O:save(path)
	local d = {}

	d.salt = self.key_info.salt
	d.key_size = tonumber(self.key_info.options.size)
	d.key_ops = tonumber(self.key_info.options.ops_limit)
	d.key_mem = tonumber(self.key_info.options.mem_limit)

	local entries, nonce = crypto.encrypt(serpent.dump(self.entries), self.key)
	d.private =
	{
		data = entries,
		nonce = nonce
	}

	do
		local s = serpent.dump(d)
		local f, e = io.open(path, "w")

		if not f then
			error(e)
		end

		f:write(s)
		f:close()
	end

	self.path = path
end

local function is_match(string, pattern)
	-- This does two things:
	-- 1) Default to a wildcard match.
	-- 2) Force the pattern to reject partial matches.
	pattern = string.format("^%s$", pattern or ".*")

	local s, r = pcall(string.match, string, pattern)

	return s and r ~= nil
end

-- Query to return the first entry matching certain parameters.
--
-- The parameters--'username', 'domain', and 'category'--are patterns to be
-- compared against each entry. If not provided, the default patterns match
-- any value.
--
-- Returns the first entry on success. On failure, returns nil.
function O:query_single(username, domain, category)
	for i = 1, #self.entries do
		local e = self.entries[i]

		if is_match(e.username, username)
			and is_match(e.domain, domain)
			and is_match(e.category, category)
		then
			return e
		end
	end

	return nil
end

-- Query to list entries matching certain parameters.
--
-- Searches the specified 'field' in the entries and compares it
-- against 'pattern'. If 'field' is 'all', then each field will be
-- compared against 'pattern'. Comparisons against 'pattern' are
-- treated as a complete match, and 'pattern' follows the Lua pattern spec.
--
-- Returns a boolean value indicating success. On failure, also returns a
-- string indicating the failure condition. On success, also returns an iterator
-- function that returns the next entry successively and nil when iteration is
-- over.
function O:query_list(field, pattern)
	field = field or 'all'

	if field ~= 'all'
		and field ~= 'username'
		and field ~= 'domain'
		and field ~= 'category'
	then
		return false, "invalid search field"
	end

	local current_index = 1
	return true, function()
		for i = current_index, #self.entries do
			local e = self.entries[i]

			local match
			if field == 'all' then
				match = is_match(e.username, pattern)
					or is_match(e.domain, pattern)
					or is_match(e.category, pattern)
			else
				match = is_match(e[field], pattern)
			end

			if match then
				current_index = i + 1

				return e
			end
		end

		return nil
	end
end

local function is_unique(entries, username, domain, category)
	for i = 1, #entries do
		local e = entries[i]

		if e.username == username
			and e.domain == domain
			and e.category == category
		then
			return false
		end
	end

	return true
end

-- Adds an entry to the database.
--
-- 'username', 'domain', and 'category' must be unique to those already in
-- the database.
--
-- Returns true on success, false on failure. On success, also returns the
-- new entry. Failure occurs when the entry already exists in the database.
function O:add_entry(username, domain, category)
	category = category or ""

	if is_unique(self.entries, username, domain, category) then
		local entry = {}

		entry.username = username
		entry.domain = domain
		entry.category = category
		entry.password = ""
		entry.note = ""
		entry.data = {}

		table.insert(self.entries, entry)

		return true, entry
	end

	return false
end

-- Removes an entry from the database.
--
-- Returns true if 'entry' was removed, false otherwise. Failure occurs if
-- 'entry' is not in the database.
function O:remove_entry(entry)
	for i = 1, #self.entries do
		if self.entries[i] == entry then
			table.remove(self.entries, i)

			return true
		end
	end

	return false
end

-- Destroys the database.
--
-- The database can no longer be saved after this operation.
function O:destroy()
	crypto.free_key(self.key)
	self.key = nil
end

local function create_database()
	local database =
	{
		key_info = {},
		entries = {}
	}

	return setmetatable(database, { __index = O })
end

local M = {}

-- Creates a new database protected by the provided passphrase.
--
-- This automatically generates a proper salt and sets the key derivation
-- parameters.
function M.create(passphrase)
	local key, salt, options = crypto.derive_key(passphrase)

	local database = create_database()
	database.key = key
	database.key_info.salt = salt
	database.key_info.options = options

	return database
end

local function read_file(path)
	local f, e = io.open(path, "r")

	if not f then
		error(e)
	end

	s = f:read("*a")
	f:close()

	return s
end

local function deserialize_public_section(section, validate)
	local success
	success, d = serpent.load(section, { safe = true })

	if not success then
		error(d)
	end

	if validate then
		if type(d.salt) ~= 'string'
			or type(d.key_size) ~= 'number'
			or type(d.key_ops) ~= 'number'
			or type(d.key_mem) ~= 'number'
			or type(d.private) ~= 'table'
			or type(d.private.data) ~= 'string'
			or type(d.private.nonce) ~= 'string'
		then
			error("invalid password database")
		end
	end

	return d
end

local function regenerate_key(passphrase, salt, size, ops_limit, mem_limit)
	return crypto.derive_key(
		passphrase,
		salt,
		{ size = size, ops_limit = ops_limit, mem_limit = mem_limit })
end

local function deserialize_private_section(section, key)
	local success, e = crypto.decrypt(section.data, section.nonce, key)

	if not success then
		return false, nil
	end

	return serpent.load(e, { safe = true })
end

local function validate_entries(entries)
	if type(entries) ~= 'table' then
		return false
	end

	for i = 1, #entries do
		if type(entries[i].username) ~= 'string' then
			return false
		end

		if type(entries[i].domain) ~= 'string' then
			return false
		end

		if entries[i].category and type(entries[i].category) ~= 'string' then
			return false
		end

		if entries[i].note and type(entries[i].note) ~= 'string' then
			return false
		end

		for key, value in pairs(entries[i].data) do
			if type(key) ~= 'string' or type(value) ~= 'string' then
				return false
			end
		end
	end

	return true
end

-- Loads a database from the provided path.
--
-- 'passphrase' will be used to decrypt the database.
--
-- Returns a boolean indicating success. On success, also returns the
-- decrypted database.
function M.load(path, passphrase)
	local database = create_database()
	database.path = path

	local section = deserialize_public_section(read_file(path), true)
	local key = regenerate_key(
		passphrase,
		section.salt,
		section.key_size,
		section.key_ops,
		section.key_mem)

	local success, entries = deserialize_private_section(section.private, key)
	if not success or not validate_entries(entries) then
		crypto.free_key(key)

		return false, nil
	end

	database.key = key
	database.key_info.salt = section.salt
	database.key_info.options =
	{
		size = section.key_size,
		ops_limit = section.key_ops,
		mem_limit = section.key_mem
	}
	database.entries = entries

	return true, database
end

return M
