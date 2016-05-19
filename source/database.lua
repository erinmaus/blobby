local crypto = require 'crypto'
local serpent = require 'serpent'

local O = {}
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
end

function O:destroy()
	crypto.free_key(self.key)
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

function M.load(path, passphrase)
	local database = create_database()

	local section = deserialize_public_section(read_file(path), true)
	local key = regenerate_key(
		passphrase,
		section.salt,
		section.key_size,
		section.ops_limit,
		section.mem_limit)

	local success, entries = deserialize_private_section(section.private, key)
	if not success or not validate_entries(entries) then
		crypto.free_key(key)

		return false, nil
	end

	database.entries = entries

	return true, database
end

return M
