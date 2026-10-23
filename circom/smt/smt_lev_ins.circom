pragma circom 2.2.2;

// Finds the level at which the queried path terminates.
//
// Vendored unchanged from
// https://github.com/iden3/circomlib/blob/master/circuits/smt/smtlevins.circom
// (only the pragma and the include of IsZero are adjusted for this repo).

include "circomlib/comparators.circom";

template SMTLevIns(nLevels) {
    signal input enabled;
    signal input siblings[nLevels];
    signal output levIns[nLevels];
    signal done[nLevels-1];        // Indicates if the insLevel has aready been detected.

    var i;

    component isZero[nLevels];

    for (i=0; i<nLevels; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== siblings[i];
    }

    // The last level must always have a sibling of 0. If not, then it cannot be inserted.
    (isZero[nLevels-1].out - 1) * enabled === 0;

    levIns[nLevels-1] <== (1-isZero[nLevels-2].out);
    done[nLevels-2] <== levIns[nLevels-1];
    for (i=nLevels-2; i>0; i--) {
        levIns[i] <== (1-done[i])*(1-isZero[i-1].out);
        done[i-1] <== levIns[i] + done[i];
    }

    levIns[0] <== (1-done[0]);
}
