# SQLite

<!--introduced_in=v22.5.0-->

<!-- YAML
added: v22.5.0
-->

> Stability: 1.1 - Active development. Enable this API with the
> [`--experimental-sqlite`][] CLI flag.

<!-- source_link=lib/sqlite.js -->

The `node:sqlite` module facilitates working with SQLite databases.
To access it:

```mjs
import sqlite from 'node:sqlite';
```

```cjs
const sqlite = require('node:sqlite');
```

This module is only available under the `node:` scheme.

The following example shows the basic usage of the `node:sqlite` module to open
an in-memory database, write data to the database, and then read the data back.

```mjs
import { DatabaseSync } from 'node:sqlite';
const database = new DatabaseSync(':memory:');

// Execute SQL statements from strings.
database.exec(`
  CREATE TABLE data(
    key INTEGER PRIMARY KEY,
    value TEXT
  ) STRICT
`);
// Create a prepared statement to insert data into the database.
const insert = database.prepare('INSERT INTO data (key, value) VALUES (?, ?)');
// Execute the prepared statement with bound values.
insert.run(1, 'hello');
insert.run(2, 'world');
// Create a prepared statement to read data from the database.
const query = database.prepare('SELECT * FROM data ORDER BY key');
// Execute the prepared statement and log the result set.
console.log(query.all());
// Prints: [ { key: 1, value: 'hello' }, { key: 2, value: 'world' } ]
```

```cjs
'use strict';
const { DatabaseSync } = require('node:sqlite');
const database = new DatabaseSync(':memory:');

// Execute SQL statements from strings.
database.exec(`
  CREATE TABLE data(
    key INTEGER PRIMARY KEY,
    value TEXT
  ) STRICT
`);
// Create a prepared statement to insert data into the database.
const insert = database.prepare('INSERT INTO data (key, value) VALUES (?, ?)');
// Execute the prepared statement with bound values.
insert.run(1, 'hello');
insert.run(2, 'world');
// Create a prepared statement to read data from the database.
const query = database.prepare('SELECT * FROM data ORDER BY key');
// Execute the prepared statement and log the result set.
console.log(query.all());
// Prints: [ { key: 1, value: 'hello' }, { key: 2, value: 'world' } ]
```

## Class: `DatabaseSync`

<!-- YAML
added: v22.5.0
-->

This class represents a single [connection][] to a SQLite database. All APIs
exposed by this class execute synchronously.

### `new DatabaseSync(location[, options])`

<!-- YAML
added: v22.5.0
-->

* `location` {string} The location of the database. A SQLite database can be
  stored in a file or completely [in memory][]. To use a file-backed database,
  the location should be a file path. To use an in-memory database, the location
  should be the special name `':memory:'`.
* `options` {Object} Configuration options for the database connection. The
  following options are supported:
  * `open` {boolean} If `true`, the database is opened by the constructor. When
    this value is `false`, the database must be opened via the `open()` method.
    **Default:** `true`.
  * `readOnly` {boolean} If `true`, the database is opened in read-only mode.
    If the database does not exist, opening it will fail. **Default:** `false`.
  * `enableForeignKeyConstraints` {boolean} If `true`, foreign key constraints
    are enabled. This is recommended but can be disabled for compatibility with
    legacy database schemas. The enforcement of foreign key constraints can be
    enabled and disabled after opening the database using
    [`PRAGMA foreign_keys`][]. **Default:** `true`.
  * `enableDoubleQuotedStringLiterals` {boolean} If `true`, SQLite will accept
    [double-quoted string literals][]. This is not recommended but can be
    enabled for compatibility with legacy database schemas.
    **Default:** `false`.

Constructs a new `DatabaseSync` instance.

### `database.close()`

<!-- YAML
added: v22.5.0
-->

Closes the database connection. An exception is thrown if the database is not
open. This method is a wrapper around [`sqlite3_close_v2()`][].

### `database.exec(sql)`

<!-- YAML
added: v22.5.0
-->

* `sql` {string} A SQL string to execute.

This method allows one or more SQL statements to be executed without returning
any results. This method is useful when executing SQL statements read from a
file. This method is a wrapper around [`sqlite3_exec()`][].

### `database.open()`

<!-- YAML
added: v22.5.0
-->

Opens the database specified in the `location` argument of the `DatabaseSync`
constructor. This method should only be used when the database is not opened via
the constructor. An exception is thrown if the database is already open.

### `database.prepare(sql)`

<!-- YAML
added: v22.5.0
-->

* `sql` {string} A SQL string to compile to a prepared statement.
* Returns: {StatementSync} The prepared statement.

Compiles a SQL statement into a [prepared statement][]. This method is a wrapper
around [`sqlite3_prepare_v2()`][].

### `database.createSession([options])`

* `options` {Object} The configuration options for the session.
  * `table` {string} A specific table to track changes for. By default, changes to all tables are tracked.
  * `db` {string} Name of the database to track. This is useful when multiple databases have been added using [`ATTACH DATABASE`][]. **Default**: `'main'`.
* Returns: {Session} A session handle.

Creates and attaches a session to the database. This method is a wrapper around [`sqlite3session_create()`][] and [`sqlite3session_attach()`][].

### `database.applyChangeset(changeset[, options])`

* `changeset` {Uint8Array} A binary changeset or patchset.
* `options` {Object} The configuration options for how the changes will be applied.
  * `filter` {Function} Skip changes that, when targeted table name is supplied to this function, return a truthy value.
    By default, all changes are attempted.
  * `onConflict` {number} Determines how conflicts are handled. **Default**: `SQLITE_CHANGESET_ABORT`.
    * `SQLITE_CHANGESET_OMIT`: conflicting changes are omitted.
    * `SQLITE_CHANGESET_REPLACE`: conflicting changes replace existing values.
    * `SQLITE_CHANGESET_ABORT`: abort on conflict and roll back databsase.
* Returns: {boolean} Whether the changeset was applied succesfully without being aborted.

An exception is thrown if the database is not
open. This method is a wrapper around [`sqlite3changeset_apply()`][].

```js
const sourceDb = new DatabaseSync(':memory:');
const targetDb = new DatabaseSync(':memory:');

sourceDb.exec('CREATE TABLE data(key INTEGER PRIMARY KEY, value TEXT)');
targetDb.exec('CREATE TABLE data(key INTEGER PRIMARY KEY, value TEXT)');

const session = sourceDb.createSession();

const insert = sourceDb.prepare('INSERT INTO data (key, value) VALUES (?, ?)');
insert.run(1, 'hello');
insert.run(2, 'world');

const changeset = session.changeset();
targetDb.applyChangeset(changeset);
// Now that the changeset has been applied, targetDb contains the same data as sourceDb.
```

## Class: `Session`

### `session.changeset()`

* Returns: {Uint8Array} Binary changeset that can be applied to other databases.

Retrieves a changeset containing all changes since the changeset was created. Can be called multiple times.
An exception is thrown if the database or the session is not open. This method is a wrapper around [`sqlite3session_changeset()`][].

### `session.patchset()`

* Returns: {Uint8Array} Binary patchset that can be applied to other databases.

Similar to the method above, but generates a more compact patchset. See [Changesets and Patchsets][]
in the documentation of SQLite. An exception is thrown if the database or the session is not open. This method is a
wrapper around [`sqlite3session_patchset()`][].

### `session.close()`.

Closes the session. An exception is thrown if the database or the session is not open. This method is a
wrapper around [`sqlite3session_delete()`][].

## Class: `StatementSync`

<!-- YAML
added: v22.5.0
-->

This class represents a single [prepared statement][]. This class cannot be
instantiated via its constructor. Instead, instances are created via the
`database.prepare()` method. All APIs exposed by this class execute
synchronously.

A prepared statement is an efficient binary representation of the SQL used to
create it. Prepared statements are parameterizable, and can be invoked multiple
times with different bound values. Parameters also offer protection against
[SQL injection][] attacks. For these reasons, prepared statements are preferred
over hand-crafted SQL strings when handling user input.

### `statement.all([namedParameters][, ...anonymousParameters])`

<!-- YAML
added: v22.5.0
-->

* `namedParameters` {Object} An optional object used to bind named parameters.
  The keys of this object are used to configure the mapping.
* `...anonymousParameters` {null|number|bigint|string|Buffer|Uint8Array} Zero or
  more values to bind to anonymous parameters.
* Returns: {Array} An array of objects. Each object corresponds to a row
  returned by executing the prepared statement. The keys and values of each
  object correspond to the column names and values of the row.

This method executes a prepared statement and returns all results as an array of
objects. If the prepared statement does not return any results, this method
returns an empty array. The prepared statement [parameters are bound][] using
the values in `namedParameters` and `anonymousParameters`.

### `statement.expandedSQL`

<!-- YAML
added: v22.5.0
-->

* {string} The source SQL expanded to include parameter values.

The source SQL text of the prepared statement with parameter
placeholders replaced by the values that were used during the most recent
execution of this prepared statement. This property is a wrapper around
[`sqlite3_expanded_sql()`][].

### `statement.get([namedParameters][, ...anonymousParameters])`

<!-- YAML
added: v22.5.0
-->

* `namedParameters` {Object} An optional object used to bind named parameters.
  The keys of this object are used to configure the mapping.
* `...anonymousParameters` {null|number|bigint|string|Buffer|Uint8Array} Zero or
  more values to bind to anonymous parameters.
* Returns: {Object|undefined} An object corresponding to the first row returned
  by executing the prepared statement. The keys and values of the object
  correspond to the column names and values of the row. If no rows were returned
  from the database then this method returns `undefined`.

This method executes a prepared statement and returns the first result as an
object. If the prepared statement does not return any results, this method
returns `undefined`. The prepared statement [parameters are bound][] using the
values in `namedParameters` and `anonymousParameters`.

### `statement.run([namedParameters][, ...anonymousParameters])`

<!-- YAML
added: v22.5.0
-->

* `namedParameters` {Object} An optional object used to bind named parameters.
  The keys of this object are used to configure the mapping.
* `...anonymousParameters` {null|number|bigint|string|Buffer|Uint8Array} Zero or
  more values to bind to anonymous parameters.
* Returns: {Object}
  * `changes`: {number|bigint} The number of rows modified, inserted, or deleted
    by the most recently completed `INSERT`, `UPDATE`, or `DELETE` statement.
    This field is either a number or a `BigInt` depending on the prepared
    statement's configuration. This property is the result of
    [`sqlite3_changes64()`][].
  * `lastInsertRowid`: {number|bigint} The most recently inserted rowid. This
    field is either a number or a `BigInt` depending on the prepared statement's
    configuration. This property is the result of
    [`sqlite3_last_insert_rowid()`][].

This method executes a prepared statement and returns an object summarizing the
resulting changes. The prepared statement [parameters are bound][] using the
values in `namedParameters` and `anonymousParameters`.

### `statement.setAllowBareNamedParameters(enabled)`

<!-- YAML
added: v22.5.0
-->

* `enabled` {boolean} Enables or disables support for binding named parameters
  without the prefix character.

The names of SQLite parameters begin with a prefix character. By default,
`node:sqlite` requires that this prefix character is present when binding
parameters. However, with the exception of dollar sign character, these
prefix characters also require extra quoting when used in object keys.

To improve ergonomics, this method can be used to also allow bare named
parameters, which do not require the prefix character in JavaScript code. There
are several caveats to be aware of when enabling bare named parameters:

* The prefix character is still required in SQL.
* The prefix character is still allowed in JavaScript. In fact, prefixed names
  will have slightly better binding performance.
* Using ambiguous named parameters, such as `$k` and `@k`, in the same prepared
  statement will result in an exception as it cannot be determined how to bind
  a bare name.

### `statement.setReadBigInts(enabled)`

<!-- YAML
added: v22.5.0
-->

* `enabled` {boolean} Enables or disables the use of `BigInt`s when reading
  `INTEGER` fields from the database.

When reading from the database, SQLite `INTEGER`s are mapped to JavaScript
numbers by default. However, SQLite `INTEGER`s can store values larger than
JavaScript numbers are capable of representing. In such cases, this method can
be used to read `INTEGER` data using JavaScript `BigInt`s. This method has no
impact on database write operations where numbers and `BigInt`s are both
supported at all times.

### `statement.sourceSQL`

<!-- YAML
added: v22.5.0
-->

* {string} The source SQL used to create this prepared statement.

The source SQL text of the prepared statement. This property is a
wrapper around [`sqlite3_sql()`][].

### Type conversion between JavaScript and SQLite

When Node.js writes to or reads from SQLite it is necessary to convert between
JavaScript data types and SQLite's [data types][]. Because JavaScript supports
more data types than SQLite, only a subset of JavaScript types are supported.
Attempting to write an unsupported data type to SQLite will result in an
exception.

| SQLite    | JavaScript           |
| --------- | -------------------- |
| `NULL`    | {null}               |
| `INTEGER` | {number} or {bigint} |
| `REAL`    | {number}             |
| `TEXT`    | {string}             |
| `BLOB`    | {Uint8Array}         |

## SQLite constants

The following constants are exported by the `node:sqlite` module.

### SQLite Session constants

#### Conflict-resolution constants

The following constants are meant for use with [`database.applyChangeset()`](#databaseapplychangesetchangeset-options).

<table>
  <tr>
    <th>Constant</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>SQLITE_CHANGESET_OMIT</code></td>
    <td>Conflicting changes are omitted.</td>
  </tr>
  <tr>
    <td><code>SQLITE_CHANGESET_REPLACE</code></td>
    <td>Conflicting changes replace existing values.</td>
  </tr>
  <tr>
    <td><code>SQLITE_CHANGESET_ABORT</code></td>
    <td>Abort when a change encounters a conflict and roll back databsase.</td>
  </tr>
</table>

[Changesets and Patchsets]: https://www.sqlite.org/sessionintro.html#changesets_and_patchsets
[SQL injection]: https://en.wikipedia.org/wiki/SQL_injection
[`--experimental-sqlite`]: cli.md#--experimental-sqlite
[`ATTACH DATABASE`]: https://www.sqlite.org/lang_attach.html
[`PRAGMA foreign_keys`]: https://www.sqlite.org/pragma.html#pragma_foreign_keys
[`sqlite3_changes64()`]: https://www.sqlite.org/c3ref/changes.html
[`sqlite3_close_v2()`]: https://www.sqlite.org/c3ref/close.html
[`sqlite3_exec()`]: https://www.sqlite.org/c3ref/exec.html
[`sqlite3_expanded_sql()`]: https://www.sqlite.org/c3ref/expanded_sql.html
[`sqlite3_last_insert_rowid()`]: https://www.sqlite.org/c3ref/last_insert_rowid.html
[`sqlite3_prepare_v2()`]: https://www.sqlite.org/c3ref/prepare.html
[`sqlite3_sql()`]: https://www.sqlite.org/c3ref/expanded_sql.html
[`sqlite3changeset_apply()`]: https://www.sqlite.org/session/sqlite3changeset_apply.html
[`sqlite3session_attach()`]: https://www.sqlite.org/session/sqlite3session_attach.html
[`sqlite3session_changeset()`]: https://www.sqlite.org/session/sqlite3session_changeset.html
[`sqlite3session_create()`]: https://www.sqlite.org/session/sqlite3session_create.html
[`sqlite3session_delete()`]: https://www.sqlite.org/session/sqlite3session_delete.html
[`sqlite3session_patchset()`]: https://www.sqlite.org/session/sqlite3session_patchset.html
[connection]: https://www.sqlite.org/c3ref/sqlite3.html
[data types]: https://www.sqlite.org/datatype3.html
[double-quoted string literals]: https://www.sqlite.org/quirks.html#dblquote
[in memory]: https://www.sqlite.org/inmemorydb.html
[parameters are bound]: https://www.sqlite.org/c3ref/bind_blob.html
[prepared statement]: https://www.sqlite.org/c3ref/stmt.html
