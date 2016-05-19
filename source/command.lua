-- Commands interface. A simple way to handle dispatching commands and parse
-- arguments.
--
-- This file is licensed under the BSD 2-Clause license.
--
-- Copyright (c) 2016 Aaron Bolyard.

local function perform_dispatch(self, ...)
	local command = select(1, ...)

	local func = self[string.lower(command)]
	if func then
		local args = { n = select("#", ...), ... }
		local function wrapper()
			return func(unpack(args, 2, args.n))
		end

		return xpcall(wrapper, debug.traceback)
	end

	return false, "command not found"
end

local M = {}

-- Creates a command object.
--
-- This object is callable, like a function. The first argument will be treated
-- as the command name. The dispatch method will return a boolean value
-- indicating success and any values returned by the invoked command. On error,
-- the boolean value will be false and an error message will be returned.
--
-- 't' should be a table that maps commands, represented as lower-case strings,
-- to commands. These commands should be callable.
--
-- Returns the command object.
function M.create(t)
	return setmetatable(t or {}, { __call = perform_dispatch })
end

-- Parses 'line' into separate arguments.
--
-- Arguments are separated by whitespace. A quote character ('"') at the
-- beginning of an argument will include all characters, including whitespace,
-- until the next quote.
--
-- Returns the arguments individually.
function M.parse_arguments(line)
	local quoted_argument = '^%s*"(.-)"'
	local plain_argument = '^%s*([^%s]+)'

	local args = {}
	local is_done = false
	repeat
		local s, e, c

		-- Advances the position to 'e + 1' and adds the match, 'c', to the
		-- argument list.
		local function add_argument()
			table.insert(args, c)
			line = string.sub(line, e + 1)
		end

		-- Attempt quoted arguments first.
		--
		-- The plain argument pattern can match quoted arguments, but quoted
		-- arguments cannot match plain arguments.
		s, e, c = string.find(line, quoted_argument)
		if s then
			add_argument()
		else
			s, e, c = string.find(line, plain_argument)

			if s then
				add_argument()
			end
		end

		is_done = not e
	until is_done

	return unpack(args)
end

return M
