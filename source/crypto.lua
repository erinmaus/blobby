-- Simple crypto interface. Provides the means to input passphrases and securely
-- encrypt/decrypt data.
--
-- This file is licensed under the BSD 2-Clause license.
--
-- Copyright (c) 2016 Aaron Bolyard.
local bit = require 'bit'
local ffi = require 'ffi'
local jit = require 'jit'

if jit.os == 'BSD' then
	ffi.cdef [[
		enum
		{
			RPP_ECHO_OFF    = 0x00,
			RPP_ECHO_ON     = 0x01,
			RPP_REQUIRE_TTY = 0x02,
			RPP_FORCELOWER  = 0x04,
			RPP_FORCEUPPER  = 0x08,
			RPP_SEVENBIT    = 0x10,
			RPP_STDIN       = 0x20
		};

		char* readpassphrase(
			const char *prompt,
			char *buf,
			size_t bufsiz,
			int flags);
	]]
else
	error("unsupported platform: no passphrase input method found")
end

ffi.cdef [[
	size_t strlen(const char* s);
]]

ffi.cdef [[
	int sodium_init(void);

	void sodium_memzero(void* const pnt, const size_t len);
	void* sodium_malloc(size_t size);
	void sodium_free(void* ptr);

	int sodium_memcmp(const void* const b1_, const void* const b2_, size_t len);
	
	char* sodium_bin2hex(
		char* const hex,
		const size_t hex_maxlen,
		const unsigned char* const bin,
		const size_t bin_len);

	int sodium_hex2bin(
		unsigned char* const bin,
		const size_t bin_maxlen,
		const char* const hex,
		const size_t hex_len,
		const char* const ignore,
		size_t* const bin_len,
		const char** const hex_end);

	void randombytes_buf(void* const buf, const size_t size);

	size_t crypto_box_seedbytes(void);
	size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);
	size_t crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);
	size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);

	size_t crypto_secretbox_keybytes(void);
	size_t crypto_secretbox_noncebytes(void);
	size_t crypto_secretbox_macbytes(void);

	int crypto_pwhash_scryptsalsa208sha256(
		unsigned char* const out,
		unsigned long long outlen,
		const char* const passwd,
		unsigned long long passwdlen,
		const unsigned char* const salt,
		unsigned long long opslimit,
		size_t memlimit);

	int crypto_secretbox_easy(
		unsigned char* c,
		const unsigned char* m,
		unsigned long long mlen,
		const unsigned char* n,
		const unsigned char* k);

	int crypto_secretbox_open_easy(
		unsigned char* m,
		const unsigned char* c,
		unsigned long long clen,
		const unsigned char* n,
		const unsigned char* k);
]]

local sodium = ffi.load("sodium")

local function create_buffer(size)
	local buffer = ffi.cast("unsigned char*", sodium.sodium_malloc(size))

	if buffer == nil then
		return false, "unable to create buffer"
	end

	return true, buffer
end

local function free_buffer(buffer)
	if buffer then
		sodium.sodium_free(buffer)
	end
end

local function generate_salt(size)
	local success, salt_buffer = create_buffer(size)

	if success then
		sodium.randombytes_buf(salt_buffer, size)
	end

	return success, salt_buffer
end

local function stringify_buffer(buffer, buffer_size)
	local string_length = buffer_size * 2 + 1
	local success, string = create_buffer(string_length)

	if not success then
		return false, "unable to create temporary string buffer"
	end

	if sodium.sodium_bin2hex(
		string,
		string_length,
		buffer,
		buffer_size) == nil
	then
		free_buffer(string)

		return false, "unable to stringify buffer"
	end

	local result = ffi.string(string)
	free_buffer(string)

	return true, result
end

local function binify_string(string, buffer_size)
	buffer_size = buffer_size or (#string / 2)
	local success, buffer = create_buffer(buffer_size)

	if not success then
		return false, "unable to create output buffer"
	end

	local temp_buffer_size = ffi.new("size_t[?]", 1, buffer_size)
	if sodium.sodium_hex2bin(
		buffer,
		buffer_size,
		string,
		#string,
		nil,
		temp_buffer_size,
		nil) ~= 0
	then
		free_buffer(buffer)

		return false, "unable to binify string"
	end

	return true, buffer, buffer_size
end

local function simple_try(func, args, failure)
	local results = { func(unpack(args)) }
	local success = results[1]

	if not success then
		if failure then
			failure()
		end

		error(results[2], 2)
	end

	return select(2, unpack(results))
end

local M = {}
M.default_password_max_size = 1024

-- Reads a passphrase.
--
-- Presents 'prompt'. The passphrase can be up to 'max_size' characters; if not
-- provided, this is 'default_password_max_size'.
--
-- The passphrase input will be masked.
--
-- Returns a password buffer. The buffer should be freeded with
-- 'free_passphrase'.
function M.read_passphrase(prompt, max_size)
	local buffer

	if jit.os == 'BSD' then
		prompt = prompt or "Enter passphrase:"
		max_size = max_size or M.default_password_max_size
		buffer = simple_try(create_buffer, { max_size }, nil)

		local flags = bit.bor(ffi.C.RPP_ECHO_OFF, ffi.C.RPP_REQUIRE_TTY)
		if ffi.C.readpassphrase(prompt, buffer, max_size, flags) == nil then
			free_buffer(buffer)

			error("could not read passphrase")
		end
	end

	return buffer
end

-- Frees a password buffer.
function M.free_passphrase(passphrase)
	free_buffer(passphrase)
end

-- Compares two passphrases for consistency.
--
-- This is only to compare passphrases for mistakes when assigning them, such
-- as to an entry or when creating a database.
--
-- Returns true if the passphrases are identical, false otherwise.
function M.compare_passphrases(a, b)
	local a_length = ffi.C.strlen(a)
	local b_length = ffi.C.strlen(b)

	if a_length ~= b_length then
		return false
	end

	return sodium.sodium_memcmp(a, b, a_length) == 0
end

-- Derives a key from a passphrase using Scrypt.
--
-- If provided, 'salt' will be used in the key derivation process; otherwise,
-- a salt will be generated.
--
-- 'options' is a table used to tune to the key derivation process. The value
-- 'mem_limit' configures memory usage and 'ops_limit' configures the
-- computation limit. 'size' determines the key size. These values should be
-- left to the defaults.
--
-- When creating a new entry database, simply providing the passphrase is enough.
-- The parameters to recreate the key will be returned.
--
-- The same passphrase will only produce the same results if 'salt' and
-- 'options' are also the same.
--
-- Returns the key buffer, salt, and key derivation options.
function M.derive_key(passphrase, salt, options)
	options = options or {}

	local salt_buffer, key_buffer
	local function on_fail()
		free_buffer(salt_buffer)
		free_buffer(key_buffer)
	end

	local default_ops =
		sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
	local default_mem =
		sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()
	local default_key_size = sodium.crypto_secretbox_keybytes()

	if salt then
		salt_buffer = simple_try(binify_string, { salt }, on_fail)
	else
		local salt_buffer_size = sodium.crypto_box_seedbytes()
		salt_buffer = simple_try(
			generate_salt,
			{ salt_buffer_size },
			on_fail)
		salt = simple_try(
			stringify_buffer,
			{ salt_buffer, salt_buffer_size },
			on_fail)
	end

	local key_options = {}
	key_options.size = options.size or default_key_size
	key_options.ops_limit = options.ops_limit or default_ops
	key_options.mem_limit = options.mem_limit or default_mem

	key_buffer = simple_try(create_buffer, { key_options.size }, on_fail)
	if sodium.crypto_pwhash_scryptsalsa208sha256(
		key_buffer,
		key_options.size,
		passphrase,
		ffi.C.strlen(passphrase),
		salt_buffer,
		key_options.ops_limit,
		key_options.mem_limit) ~= 0
	then
		on_fail()

		error("couldn't derive key from passphrase")
	end
	free_buffer(salt_buffer)

	return key_buffer, salt, key_options
end

-- Frees a key returned by 'derive_key'.
function M.free_key(key)
	free_buffer(key)
end

-- Encrypts data with the provided key.
--
-- Returns the encrypted data and nonce. The nonce is necessary to decrypt the
-- data later.
function M.encrypt(data, key)
	local data_buffer, nonce_buffer
	local function on_fail()
		free_buffer(data_buffer)
		free_buffer(nonce_buffer)
	end

	local data_buffer_size = sodium.crypto_secretbox_macbytes() + #data
	local nonce_buffer_size = sodium.crypto_secretbox_noncebytes()

	data_buffer = simple_try(create_buffer, { data_buffer_size }, on_fail)
	nonce_buffer = simple_try(generate_salt, { nonce_buffer_size }, on_fail)

	if sodium.crypto_secretbox_easy(
		data_buffer,
		data,
		#data,
		nonce_buffer,
		key) ~= 0
	then
		on_fail()

		error("couldn't encrypt data")
	end

	local stringified_data = simple_try(
		stringify_buffer, 
		{ data_buffer, data_buffer_size },
		on_fail)
	local stringified_nonce = simple_try(
		stringify_buffer,
		{ nonce_buffer, nonce_buffer_size },
		on_fail)

	free_buffer(data_buffer)
	free_buffer(nonce_buffer)

	return stringified_data, stringified_nonce
end

-- Decrypts data with the provided nonce and key.
--
-- Returns two values: a boolean value indicating success and the decrypted
-- data, as a string. If the operation fails, the boolean value will be 'false'
-- and the data will be nil.
function M.decrypt(data, nonce, key)
	local data_buffer, nonce_buffer, output_buffer
	local function on_fail()
		free_buffer(data_buffer)
		free_buffer(nonce_buffer)
		free_buffer(output_buffer)
	end

	local data_buffer_size, nonce_buffer_size
	data_buffer, data_buffer_size = simple_try(binify_string, { data }, on_fail)
	nonce_buffer, nonce_buffer_size = simple_try(binify_string, { nonce }, on_fail)

	local output_buffer_size = data_buffer_size - sodium.crypto_secretbox_macbytes()
	output_buffer = simple_try(create_buffer, { output_buffer_size}, on_fail)

	if sodium.crypto_secretbox_open_easy(
		output_buffer,
		data_buffer,
		data_buffer_size,
		nonce_buffer,
		key) ~= 0
	then
		on_fail()

		return false, nil
	end

	local output_data = ffi.string(output_buffer, output_buffer_size)
	free_buffer(data_buffer)
	free_buffer(nonce_buffer)
	free_buffer(output_buffer)

	return true, output_data
end

if sodium.sodium_init() == -1 then
	error("couldn't initialize crypto library")
end

return M
