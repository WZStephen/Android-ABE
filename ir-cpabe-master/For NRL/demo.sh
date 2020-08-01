#!/bin/bash

python3 gp_setup.py;

python3 federated_setup.py;

rm ta*.pk;

python3 federated_keygen.py;

rm ta*.org.sk

python3 internal_delegation.py;

cp attributes_map.json global.param pk.param test/;

python3 external_delegation.py;
