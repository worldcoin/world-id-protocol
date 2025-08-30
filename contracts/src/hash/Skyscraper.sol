// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

library Skyscraper {
    // BN254 field modulus
    uint256 internal constant P =
        21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;

    uint256 internal constant SIGMA_INV =
        9_915_499_612_839_321_149_637_521_777_990_102_151_350_674_507_940_716_049_588_462_388_200_839_649_614;

    // Non-zero round constants
    uint256 internal constant RC_1 =
        17_829_420_340_877_239_108_687_448_009_732_280_677_191_990_375_576_158_938_221_412_342_251_481_978_692;
    uint256 internal constant RC_2 =
        5_852_100_059_362_614_845_584_985_098_022_261_541_909_346_143_980_691_326_489_891_671_321_030_921_585;
    uint256 internal constant RC_3 =
        17_048_088_173_265_532_689_680_903_955_395_019_356_591_870_902_241_717_143_279_822_196_003_888_806_966;
    uint256 internal constant RC_4 =
        71_577_923_540_621_522_166_602_308_362_662_170_286_605_786_204_339_342_029_375_621_502_658_138_039;
    uint256 internal constant RC_5 =
        1_630_526_119_629_192_105_940_988_602_003_704_216_811_347_521_589_219_909_349_181_656_165_466_494_167;
    uint256 internal constant RC_6 =
        7_807_402_158_218_786_806_372_091_124_904_574_238_561_123_446_618_083_586_948_014_838_053_032_654_983;
    uint256 internal constant RC_7 =
        13_329_560_971_460_034_925_899_588_938_593_812_685_746_818_331_549_554_971_040_309_989_641_523_590_611;
    uint256 internal constant RC_8 =
        16_971_509_144_034_029_782_226_530_622_087_626_979_814_683_266_929_655_790_026_304_723_118_124_142_299;
    uint256 internal constant RC_9 =
        8_608_910_393_531_852_188_108_777_530_736_778_805_001_620_473_682_472_554_749_734_455_948_859_886_057;
    uint256 internal constant RC_10 =
        10_789_906_636_021_659_141_392_066_577_070_901_692_352_605_261_812_599_600_575_143_961_478_236_801_530;
    uint256 internal constant RC_11 =
        18_708_129_585_851_494_907_644_197_977_764_586_873_688_181_219_062_643_217_509_404_046_560_774_277_231;
    uint256 internal constant RC_12 =
        8_383_317_008_589_863_184_762_767_400_375_936_634_388_677_459_538_766_150_640_361_406_080_412_989_586;
    uint256 internal constant RC_13 =
        10_555_553_646_766_747_611_187_318_546_907_885_054_893_417_621_612_381_305_146_047_194_084_618_122_734;
    uint256 internal constant RC_14 =
        18_278_062_107_303_135_832_359_716_534_360_847_832_111_250_949_377_506_216_079_581_779_892_498_540_823;
    uint256 internal constant RC_15 =
        9_307_964_587_880_364_850_754_205_696_017_897_664_821_998_926_660_334_400_055_925_260_019_288_889_718;
    uint256 internal constant RC_16 =
        13_066_217_995_902_074_168_664_295_654_459_329_310_074_418_852_039_335_279_433_003_242_098_078_040_116;

    uint256 internal constant MASK_L1 = 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;
    uint256 internal constant MASK_H1 = 0x8080808080808080808080808080808080808080808080808080808080808080;
    uint256 internal constant MASK_L2 = 0x3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F;
    uint256 internal constant MASK_H2 = 0xC0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0;
    uint256 internal constant MASK_L3 = 0x1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F;
    uint256 internal constant MASK_H3 = 0xE0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0;

    function compress(uint256 l, uint256 r) public pure returns (uint256) {
        uint256 t = l;
        (l, r) = permute(l, r);
        return addmod(t, l, P);
    }

    function compress_sigma(uint256 l, uint256 r) public pure returns (uint256) {
        uint256 t = l;
        (l, r) = permute_sigma(l, r);
        return addmod(t, l, P);
    }

    // SkyscraperV2 over Bn254 scalar field with no Montgomery factor.
    // Requires l and r to be in the range [0, P-1].
    function permute(uint256 l, uint256 r) internal pure returns (uint256, uint256) {
        (l, r) = ss(l, r, 0, RC_1);
        (l, r) = ss(l, r, RC_2, RC_3);
        (l, r) = ss_reduce_l(l, r, RC_4, RC_5);
        (l, r) = bb(l, r, RC_6, RC_7);
        (l, r) = ss_reduce_l(l, r, RC_8, RC_9);
        (l, r) = bb(l, r, RC_10, RC_11);
        (l, r) = ss(l, r, RC_12, RC_13);
        (l, r) = ss(l, r, RC_14, RC_15);
        (l, r) = ss(l, r, RC_16, 0);
        return (l, r);
    }

    // SkyscraperV2 over Bn254 scalar field with Montgomery factor.
    // Requires l and r to be in the range [0, P-1].
    function permute_sigma(uint256 l, uint256 r) internal pure returns (uint256, uint256) {
        (l, r) = sss(l, r, 0, RC_1);
        (l, r) = sss(l, r, RC_2, RC_3);
        (l, r) = sss_reduce_l(l, r, RC_4, RC_5);
        (l, r) = bb(l, r, RC_6, RC_7);
        (l, r) = sss_reduce_l(l, r, RC_8, RC_9);
        (l, r) = bb(l, r, RC_10, RC_11);
        (l, r) = sss(l, r, RC_12, RC_13);
        (l, r) = sss(l, r, RC_14, RC_15);
        (l, r) = sss(l, r, RC_16, 0);
        return (l, r);
    }

    function ss(uint256 l, uint256 r, uint256 rc_a, uint256 rc_b) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(l, l, P), r, P);
            l = rc_b + addmod(mulmod(r, r, P), l, P);
        }
        return (l, r);
    }

    function ss_reduce_l(uint256 l, uint256 r, uint256 rc_a, uint256 rc_b) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(l, l, P), r, P);
        }
        l = addmod(rc_b, addmod(mulmod(r, r, P), l, P), P);
        return (l, r);
    }

    function sss(uint256 l, uint256 r, uint256 rc_a, uint256 rc_b) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(mulmod(l, l, P), SIGMA_INV, P), r, P);
            l = rc_b + addmod(mulmod(mulmod(r, r, P), SIGMA_INV, P), l, P);
        }
        return (l, r);
    }

    function sss_reduce_l(uint256 l, uint256 r, uint256 rc_a, uint256 rc_b) internal pure returns (uint256, uint256) {
        unchecked {
            r = rc_a + addmod(mulmod(mulmod(l, l, P), SIGMA_INV, P), r, P);
        }
        l = addmod(rc_b, addmod(mulmod(mulmod(r, r, P), SIGMA_INV, P), l, P), P);
        return (l, r);
    }

    // Requires l to be reduced.
    function bb(uint256 l, uint256 r, uint256 rc_a, uint256 rc_b) internal pure returns (uint256, uint256) {
        uint256 x = (l << 128) | (l >> 128); // Rotate left by 128 bits
        uint256 x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7); // Bytewise rotate left 1
        uint256 x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);
        uint256 x3 = x1 & x2;
        uint256 x4 = ((x3 & MASK_L2) << 2) | ((x3 & MASK_H2) >> 6);
        x = x1 ^ ((~x2) & x4);
        r = addmod(rc_a, addmod(x, r, P), P);

        x = (r << 128) | (r >> 128); // Rotate left by 128 bits
        x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7); // Bytewise rotate left 1
        x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);
        x3 = x1 & x2;
        x4 = ((x3 & MASK_L2) << 2) | ((x3 & MASK_H2) >> 6);
        x = x1 ^ ((~x2) & x4);
        unchecked {
            l = rc_b + addmod(x, l, P);
        }
        return (l, r);
    }

    function bar(uint256 x) internal pure returns (uint256) {
        x = (x << 128) | (x >> 128); // Rotate left by 128 bits
        uint256 x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7); // Bytewise rotate left 1
        uint256 x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);
        uint256 x3 = x1 & x2;
        uint256 x4 = ((x3 & MASK_L2) << 2) | ((x3 & MASK_H2) >> 6);
        return x1 ^ ((~x2) & x4);
    }

    // SWAR 32-byte parallel SBOX.
    function sbox(uint256 x) internal pure returns (uint256) {
        uint256 x1 = ((x & MASK_L1) << 1) | ((x & MASK_H1) >> 7);
        uint256 x2 = ((x1 & MASK_L1) << 1) | ((x1 & MASK_H1) >> 7);

        uint256 t = x & x1;
        t = ((t & MASK_L3) << 3) | ((t & MASK_H3) >> 5);

        return x1 ^ ((~x2) & t);
    }

    // Bitwise rotate a byte left one place, rotates 32 bytes in parallel using SWAR.
    function rot1(uint256 x) internal pure returns (uint256) {
        uint256 left = (x & MASK_L1) << 1;
        uint256 right = (x & MASK_H1) >> 7;
        return left | right;
    }
}
