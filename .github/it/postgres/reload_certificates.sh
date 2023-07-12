#!/bin/sh

psql -c 'SELECT pg_reload_conf();'
