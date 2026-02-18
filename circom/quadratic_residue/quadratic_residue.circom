pragma circom 2.2.2;
include "circomlib/comparators.circom";

// Returns the Legendre symbol of n in F_r:
// -  1 if n is a quadratic residue and n != 0
// - -1 if n is a non-quadratic residue
// -  0 if n == 0
function bbf_legendre(n) {
    if (n == 0) {
        return 0;
    } else {
        return n ** ((-1) >> 1);
    }
}

// Returns 1 if the input is either 0 or 1; otherwise returns 0.
template IsZeroOrOne() {
    signal input in;
    signal output out;
    out <== IsZero()(in * in - in);
}

// Constrain that x ∈ {0, 1, -1} in F_r by enforcing:
// x(x - 1)(x + 1) == 0
// This template adds constraints only; it returns no output value.
template CheckZeroOneOrMinusOne() {
    signal input in;
    signal lhs <== in * (in - 1);
    signal rhs <== in + 1;
    lhs * rhs === 0;
}

function bbf_sqrt_input(l, a, na) {
    if (l != -1) {
        return a;
    } else {
        return na;
    }
}

// This function returns sqrt(n) using Tonelli–Shanks parameters for BN254.
// It does NOT check whether n is a quadratic residue in the BN254 scalar field.
// Calling this function without checking the Legendre symbol results in undefined behavior.
function bbf_sqrt_unchecked(n) {
    if (n == 0) {
        return 0;
    }

    var m = 28;
    var c = 19103219067921713944291392827692070036145651957329286315305642004821462161904;
    var t = n ** 81540058820840996586704275553141814055101440848469862132140264610111;
    var r = n ** ((81540058820840996586704275553141814055101440848469862132140264610111+1)>>1);
    var sq;
    var i;
    var b;
    var j;

    while ((r != 0)&&(t != 1)) {
        sq = t*t;
        i = 1;
        while (sq!=1) {
            i++;
            sq = sq*sq;
        }

        // b = c ^ m-i-1
        b = c;
        for (j=0; j< m-i-1; j ++) b = b*b;

        m = i;
        c = b*b;
        t = t*c;
        r = r*b;
    }


    return r;
}

// Returns 0 or 1 depending on whether the provided number `a` is a quadratic
// residue (including zero) in the BN254 scalar field.
//
// Definitions:
// - a is a quadratic residue if there exists b such that b^2 ≡ a (mod p).
// - a is a non-quadratic residue if there exists a non-residue n and b such that b^2 ≡ a*n (mod p).
//
// Constraint strategy, from (<https://eprint.iacr.org/2021/984.pdf>, page 4):
// Let l = Legendre(a) ∈ { -1, 0, 1 }.
// Introduce a witness b intended to be a square root:
// Enforce: l(l-1)(b^2 - n*a) + (l+1)(b^2 - a) == 0
// For l =  1: (l(l-1)) = 0 and (l+1) = 2 => b^2 = a
// For l = -1: (l(l-1)) = 2 and (l+1) = 0 => b^2 = n*a
// For l =  0: (l(l-1)) = 0 and (l+1) = 1 => b^2 = a (which forces a to be 0 or a quadratic residue)
// Note that the above checks from the paper would also allow for a=0,b=0, but l=-1.
// Therefore we add another constraint enforcing a=0 => l=0, see below.
template IsQuadraticResidueOrZero() {
    signal input a;
    signal output out;

    // Compute Legendre symbol l
    signal l <-- bbf_legendre(a);

    // Constraint a=0 => l=0
    component isZeroA = IsZero();
    isZeroA.in <== a;
    // at least one of l and (isZero(a)) need to be 0
    // This disallows the case of l!=0 and a==0, the case l==0 and a==0 is as expected, same with l!=0 and a!=0.
    // There is still the case of l==0 and a!=0 which would be allowed by this and would give an invalid legendre symbol for a.
    // However we enforce in that case (l = 0) that a = b^2, which still produces the correct high-level output for this gadget,
    // since l in {0,1} and we do not directly return l.
    isZeroA.out * l === 0;

    // Constrain l ∈ { -1, 0, 1 }
    component legendre_check = CheckZeroOneOrMinusOne();
    legendre_check.in <== l;

    // n is the smallest non-quadratic residue in BN254
    var n = 5;
    signal na <== n * a;

    // Witness for a square root under the appropriate condition
    var sqrt_input = bbf_sqrt_input(l, a, na);
    // We don't use the ternary operator because Circom evaluates both branches which results in endless loops.
    signal b <-- bbf_sqrt_unchecked(sqrt_input);

    // Compute the selectors
    signal s_na <== l * (l - 1); // 0 when l ∈ {0,1}, 2 when l = -1
    signal s_a <== l + 1; // 0 when l = -1, 1 when l = 0, 2 when l = 1

    // Compute the respective constraints 
    signal b2 <== b * b;
    signal c_na <== b2 - na;
    signal c_a <== b2 - a;

    // Enforce the constraint
    signal lhs <== s_na * c_na; 
    signal rhs <== s_a * c_a; 
    lhs + rhs === 0;

    // Output 1 iff l ∈ {0, 1} (i.e., a is a quadratic residue or zero), else 0
    out <== IsZeroOrOne()(l);
}
