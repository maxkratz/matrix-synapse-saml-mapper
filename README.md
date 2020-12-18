# Matrix Synapse SAML Mapper

A Synapse plugin module which allows administrators to ...
* ... concatenate and/or modify provided SAML attributes,
* ... log registrations to a custom logfile and
* ... log user SAML attributes to a custom PostgreSQL database at their initial login.

The main reason for creating this project was the fact, that the identity prodivder at TU Darmstadt does **not** provide an easy to read "displayName" as SAML attribute.
Therefore, I had to concatenate first- and surname(s) together.

Please notice, that the custom PostgreSQL database is **not** the same database as the one used by your Synapse installation!

Another **important notice**:
This code may break unexpectedly.
Please use this project as a kind of blueprint to implement your own SAML mapper.
Of course you are allowed to also use it in production environments, but you've been warned :).


## Installation

* Clone this repository to your local python workspace: `$ git clone https://github.com/maxkratz/matrix-synapse-saml-mapper.git`
* Adapt `module_config.yml` according to your needs.
* Install all dependencies with `$ pip3 install -r requirements.txt`.
* Run `$ python3 setup.py sdist bdsist_wheel`.
* Copy built files/folders to your system running Synapse.
* Install the package in your virtual environment.
    * E.g. for a Matrix installation based on the Debian/Ubuntu package, run `$ /opt/venvs/matrix-synapse/bin/python setup.py install` in your console.

### Database setup

In order to use this module to log new user registrations (from SAML) to a custom PostgreSQL database, you have to set it up.

Keep in mind, that this custom database logging of users is just an additional feature of this module.
You can always remove/comment out some code if you do not need it.

* Login e.g. with `$ su - root`.
* Create user: `$ createuser --pwprompt ou_user`
* Login into PostgreSQL:
    * `$ su - postgres`
    * `$ psql`
* Create database: `=# CREATE DATABASE ou ENCODING 'UTF8' template=template0 OWNER ou_user;`
* Connect to database: `=# \connect ou`
* Create table with followoing design:
  * `id` is a unique primary key for all entries.
  * `tuid` is a char with 8 symbols for the unique id at TU Darmstadt. Feel free to change it here **and** within the code according to your needs.
    * The constraint at the end ensures that this field is always unique.
  * `ou` is an array of text for all departments and organizations etc.
  * `givenname` is a text for all first names (TU Darmstadts idp concatenates first names together).
  * `surname` is a text for all surnames (TU Darmstadts idp concatenates surnames together).
  * `email` is an array of text for all email addresses of a person.
  * `edu_person_affiliation` is an array of text for all groups e.g. *student* and *member*.
  * `created_at` is the timestamp of the insert into this table.

```
=# CREATE TABLE user_external_saml (
  id SERIAL PRIMARY KEY NOT NULL,
  tuid char(8) NOT NULL,
  ou TEXT[] NOT NULL,
  givenname TEXT NOT NULL,
  surname TEXT NOT NULL,
  email TEXT[] NOT NULL,
  edu_person_affiliation TEXT[] NOT NULL,
  created_at TIMESTAMP NOT NULL,
  CONSTRAINT tuid_unique UNIQUE (tuid)
);
```

* Change table owner to `ou_user`: `=# ALTER TABLE user_external_saml OWNER TO ou_user;`
* Add user `ou_user` to your PostgreSQL database. In my case, this was done by extending `/etc/postgresql/12/main/pg_hba.con`:
```
hostssl ou              ou_user         <synapse-server-ip>/32       md5
```

* Restart PostgreSQL: `$ service postgresql restart`

### Logging setup

The logging capability of this module is more a kind of 'conceptual proof'.
If properly set up, the module logs all unique ids together with the timestamp of their first login (registration) to a log file onto disk.

Keep in mind, that this custom file logging of users is just an additional feature of this module.
You can always remove/comment out some code if you do not need it.

* `$ mkdir -p /var/log/custom-scripts`
* `$ chown -R matrix-synapse /var/log/custom-scripts/`
* `$ chgrp -R nogroup /var/log/custom-scripts/`

Logs can be found in `/var/log/custom-scripts/dummy_logger.log`


## Configuration

Configuration of this module is completely done inside file `module_config.yml`.

### Database

* `db: database: "ou"` Module uses a custom PostgreSQL database with name *ou*.
* `db: user: "ou_user"` Module uses a custom PostgreSQL database user named *ou_user*.
* `db: password: "secret"` Module uses a custom PostgreSQL database password *secret*.
* `db: host: "db-host"` Module uses a custom PostgreSQL database at host *db-host*. (You may also specify an ip address here.)
* `db: port: "5432"` Module uses the given port to connect to custom PostgreSQL database.

### Logging

* `log: path: "/var/log/custom-scripts/dummy_logger.log"` Module uses the specified path to log new registrations (user creations at first login) of SAML to specified file.

### Synapse

In order to use the custom module, you have configure Synapse to do so.
For this example, lets assume the following attributes provided by the identity provider:

* `cn`: This is the unique id, in most systems named *uid*.
* `mail`: Mail address of the user.
* `surname`: Surname(s) of the user.
* `givenName`: Given name(s) of the user.

Change the SAML2 attribute map in `/etc/matrix-synapse/saml2-attribute-maps/map.py`:

```
MAP = {
    "identifier": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
    "fro": {
        'cn': 'uid',
        'mail': 'email',
        'surname': 'surname',
        'givenName': 'givenName',
    },
    "to": {
        'uid': 'cn',
        'mail': 'email',
        'surname': 'surname',
        'givenName': 'givenName',
    },
}
```

Please keep in mind that this module expects this four values (after mapping):

* `uid`
* `email`
* `surname`
* `givenName`

Edit the following values in your `homeserver.yml` file:

```
saml2_config:
    # [...]
    attribute_map_dir: /etc/matrix-synapse/saml2-attribute-maps
    # [...]

  user_mapping_provider:
    module: "matrix_synapse_saml_mapper.SamlMappingProvider"
    config:
      mxid_source_attribute: uid
```

Restart your Synapse server after all configuration changes.


## Codestyle

Code is linted with `pylint` using *pep8* style.
You may check the style using this command:

`pylint-fail-under --fail_under 9.0 -d pep8 matrix_synapse_saml_mapper/*.py setup.py`


## References

This code is heavily based on:
* https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md
* https://github.com/matrix-org/matrix-synapse-saml-mozilla
* https://github.com/chaos-jetzt/matrix-synapse-saml-mapper

Please check out the following plugin, if you want to **trace SAML logins** (on the client side).
At least for me, it was really helpful while debugging.
* https://github.com/UNINETT/SAML-tracer
