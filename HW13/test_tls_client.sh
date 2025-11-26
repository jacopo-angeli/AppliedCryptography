#!/bin/bash


echo "=====> Testing OK [1021-bit RSA key]"
gnome-terminal --window -- bash -lc "./tls_server --port 4433 --keysize 1021; echo; echo 'Server 4433 exited. Press Enter to close'; read"
sleep 1
./tls_client.py https://127.0.0.1:4433/
read

echo "=====> Testing OK [2048-bit RSA key]"
gnome-terminal --window -- bash -lc "./tls_server --port 4433 --keysize 2048; echo; echo 'Server 4433 exited. Press Enter to close'; read"
sleep 1
./tls_client.py https://127.0.0.1:4433/
read

echo "=====> Testing OK [4096-bit RSA key]"
gnome-terminal --window -- bash -lc "./tls_server --port 4433 --keysize 4096; echo; echo 'Server 4433 exited. Press Enter to close'; read"
sleep 1
./tls_client.py https://127.0.0.1:4433/
read

echo "=====> Testing MAC fail"
gnome-terminal --window -- bash -lc "./tls_server --port 4434 --macfail; echo; echo 'Server 4433 exited. Press Enter to close'; read"
sleep 1
./tls_client.py https://127.0.0.1:4434/
read

echo "=====> Testing verify fail"
gnome-terminal --window -- bash -lc "./tls_server --port 4435 --verifyfail; echo; echo 'Server 4433 exited. Press Enter to close'; read"
sleep 1
./tls_client.py https://127.0.0.1:4435/
read

echo "=====> Testing https://baidu.com/"
./tls_client.py https://baidu.com/
read
