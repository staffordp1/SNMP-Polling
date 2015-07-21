# SNMP-Polling
SNMP Polling application, written in C++



INSTALLATION

Create the PostgreSQL database
--------------------------------------------------------------------------------
Installation notes:
-- Install PostgreSQL
-- as user postgres (su - postgres) initialize the database:
 initdb -D /var/lib/pgsql/data
 pg_ctl start
-- create the database NAC and user nacmgr:
 createuser  --no-adduser --no-createdb --pwprompt --encrypted nacmgr
 createdb --owner=nacmgr NAC
 psql -U nacmgr -d NAC

-- start the database:
 pg_ctl start -D ~postgres/pgsql/data -l logfile

-- set the password for nacmgr
 ALTER USER nacmgr with PASSWORD 'password';

-- Use the following query when I run into locking troubles.
This query gives you lock information for both the relations and the transactions.

 select pg_stat_activity.datname,pg_class.relname, pg_locks.mode, pg_locks.granted,pg_stat_activity.usename,substr(pg_stat_activity.current_query,1,30), pg_stat_activity.query_start, age(now(),pg_stat_activity.query_start) as "age", pg_stat_activity.procpid from pg_stat_activity,pg_locks left outer join pg_class on (pg_locks.relation = pg_class.oid)  where pg_locks.pid=pg_stat_activity.procpid order by query_start;

