pragma circom 2.2.2;

include "oprf_keys/keygen.circom";

component main {public [degree, pks, nonces]} = KeyGen(6, 9);
