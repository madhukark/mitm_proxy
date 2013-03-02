#!/bin/bash

./setup.bash

java mitm.MITMProxyServer -keyStore ./keystore -keyStorePassword password
