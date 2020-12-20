# Matrix Synapse SAML Mapper

[![Build Status](https://github.ci.maxkratz.com/api/badges/maxkratz/matrix-synapse-saml-mapper/status.svg?ref=refs/heads/main)](https://github.ci.maxkratz.com/maxkratz/matrix-synapse-saml-mapper)

A Synapse plugin module which allows administrators to ...
* ... concatenate and/or modify provided SAML attributes,
* ... log registrations to a custom logfile and
* ... log user SAML attributes to a custom PostgreSQL database at their initial login.

The main reason for creating this project was the fact that the identity provider (idp) at the [Technical University (TU) Darmstadt](https://www.tu-darmstadt.de/index.en.jsp) does **not** provide an easy to read "displayName" as a SAML attribute.
Therefore,  first- and surname(s) had to be concatenated manually to populate the "displayName" fields.
Some code snippets found herein refer to an identification named *TU-ID* which is the unique id for all students and employees at our university.
This attribute will most likely be called *uid* within your SAML provider.

Please note that the custom PostgreSQL database is **not** the same database as the one used by your Synapse installation!

Another **important note**:
This code may break unexpectedly.
Feel free to use this project as a kind of blueprint to implement your own SAML mapper.
You are of course allowed to also use it in production environments, but you've been warned. :)


## Installation

* Clone this repository to your python workspace
    * e.g. `$ git clone https://github.com/maxkratz/matrix-synapse-saml-mapper.git`
* Adapt `module_config.yml` according to your needs.
* Install the package in your virtual environment which is used by Synapse.
    * e.g. for a Matrix/Synapse installation based on the Debian/Ubuntu package, run `$ /opt/venvs/matrix-synapse/bin/python setup.py install` on your console.

### Logging setup
Keep in mind that this custom logging of users is just an additional feature of this module.
You can always remove/comment out these parts if you will not make any use of it.

#### Logging setup: Database

In order to use this module to log new user registrations (from SAML) to a custom PostgreSQL database, you have to set this database up first.
For this example I will use the name `ou` (which stands for *organizational unit*), but feel free to change these values to your liking.

* Login (e.g. with `$ su - root`).
* Create user: `$ createuser --pwprompt ou_user`
* Login to PostgreSQL:
    * `$ su - postgres`
    * `$ psql`
* Create database: `=# CREATE DATABASE ou ENCODING 'UTF8' template=template0 OWNER ou_user;`
* Connect to database: `=# \connect ou`
* Create table with following design:
  * `id` is a unique primary key for all entries.
  * `tuid` is a char with 8 symbols for the unique id at [Technical University (TU) Darmstadt](https://www.tu-darmstadt.de/index.en.jsp). Feel free to change this here **and** within the code according to your needs.
    * A constraint at the end to ensure that this field is always unique.
  * `ou` is an array of text for all departments and organizations etc.
  * `givenname` is a text for all first names ([Technical University (TU) Darmstadt](https://www.tu-darmstadt.de/index.en.jsp) idp concatenates first names together).
  * `surname` is a text for all surnames ([Technical University (TU) Darmstadt](https://www.tu-darmstadt.de/index.en.jsp) idp concatenates surnames together).
  * `email` is an array of text for all email addresses of a person.
  * `edu_person_affiliation` is an array of text for all groups, e.g. *student* and *member*.
  * `created_at` is the timestamp of the insertion into this table.

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

#### Logging setup: Actual logging

The logging capability of this module is more of a 'conceptual proof'.
If properly set up, the module logs all unique ids together with the timestamp of their first login (registration) to a log file onto disk.

* `$ mkdir -p /var/log/custom-scripts`
* `$ chown -R matrix-synapse /var/log/custom-scripts/`
* `$ chgrp -R nogroup /var/log/custom-scripts/`

Logs can be found in `/var/log/custom-scripts/dummy_logger.log` (default path).


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
For this example let's assume the following attributes provided by the identity provider (idp):

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

Code is linted with `pylint` using *PEP 8* style.
You may check the style using this command:

`pylint-fail-under --fail_under 9.0 -d pep8 matrix_synapse_saml_mapper/*.py setup.py`


## References

This code is heavily based on:
* https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md
* https://github.com/matrix-org/matrix-synapse-saml-mozilla
* https://github.com/chaos-jetzt/matrix-synapse-saml-mapper

Please check out the following plugin if you want to **trace SAML logins** (on the client side).
At least for me it was quite helpful during debugging.
* https://github.com/UNINETT/SAML-tracer
