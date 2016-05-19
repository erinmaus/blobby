# Blobby
Very simple password manager written in Lua. Uses the Sodium crypto library.

This password manager was made only for my personal use. No guarantees are made
of the security, reliability, or benefits of this utility.

If you want to manage passwords, don't use Blobby. Instead, use a
tried-and-tested utility.

# Requirements
Blobby requires LuaJIT 2 and the Sodium crypto library.

Currently, it also requires support for the extension `readpassphrase`, found
in FreeBSD, OpenBSD, and others. Copying the password to the clipboard also
requires X11 support.

# Usage

Run Blobby:

```
$ blobby <open/create/help> [path]
```

'open' will read the password database at 'path'. A master passphrase will be
requested to decrypt the database.

'create' will create a new password database. The master passphrase will be
requested twice. The database will be created.

'help' will show a simple help message with this information.

Only 'open' will begin a session. In essence, this means the master passphrase
must be entered three times--twice on creation, and once to begin a session.

A session is an interactive prompt that lets you view and modify the password
database by entering various commands with arguments. Arguments are strings
unless otherwise stated.

The quote character, '"', can be used for strings with spaces. For example, to
supply the words _Sir Bob_ as a single argument with a space, simple type
`"Sir Bob"`.

You can `list` entries in the database:

```
> list [all, domain, username, category] [pattern]
```

If no arguments are provided, the default is 'all'. The 'pattern' argument is
identical to the syntax of Lua patterns (see
[section 2.4.1](http://www.lua.org/manual/5.1/manual.html#5.4.1) for syntax).

You can `view` a specific entry in the database:

```
> view [username] [domain] [category]
```

Only the first matched result is shown. Any sensitive data is hidden.

The result is treated as the active entry. If no arguments are provided, the
currently active entry will be shown.

You can `copy` data to the clipboard:

```
> copy <password, note, data> <id> [username] [domain] [category]
```

If no search parameters are provided, the active entry is used. Otherwise, the
data from the first matched result is copied.

The 'id' argument is only needed if copying 'data'.

Alternatively, `show` can be used to print the data directly to the console. It
behaves identically to `copy` otherwise.

You can `edit` an entry:

```
> edit <password, note, data> <id> [username] [domain] [category]
```

If no search parameters are provided, the active entry is used. Otherwise, the
first matched entry is modified.

The 'id' argument is only needed is editing 'data'. It is treated as a string.
To use spaces, enclose 'id' in quotes (", ASCII 0x22).

You can `add` an entry:

```
> add <username> <domain> [category]
```

If an entry already exists, nothing will happen. No password, note, or data will
be associated with the entry.

## Passwords
Passwords (or data) can be manually specified or automatically generated using
`edit`.

If generated, some questions will be asked about the password requirements.
Afterwards, the password will be stored. It can be retrieved with `copy` or
`show`.

# License
Blobby is licensed under the BSD 2-Clause license. View LICENSE in the root
directory for more information.