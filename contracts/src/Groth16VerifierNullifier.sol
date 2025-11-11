// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 7518643722019743679149176996916037154186308319346620625076052818603513516278;
    uint256 constant alphay = 895855018487306536042334465376055057730586353119497393704693169012791602177;
    uint256 constant betax1 = 20817844202387277345283051960273302333801861478713116998305330480129662603039;
    uint256 constant betax2 = 1195341196710889580062208403574255938308923979711528448621875846792718813199;
    uint256 constant betay1 = 12053872034956751315902004838386039218818620905205895914789206927410175752947;
    uint256 constant betay2 = 9743177914465950047848412050863152784917524102428097254989719783562540278775;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 5945629923307235923721579927539751120478089701190090965773697955302090632965;
    uint256 constant deltax2 = 1222444380784454041157375184294717192977650618322580122994266765302732305769;
    uint256 constant deltay1 = 9103181462424713989982763444610423393229483675451182568513030674132610487589;
    uint256 constant deltay2 = 10088512366063812791548585302955607239339805374202935559383480125816445506398;

    uint256 constant IC0x = 2328243743958523339325843896003949469530738724175619315840172161684586945509;
    uint256 constant IC0y = 476568148040073523039536574931298689924442281726389774145288704103691693911;

    uint256 constant IC1x = 4435020844403009769089689984180865531788313345374722687253647167432891548965;
    uint256 constant IC1y = 723169795643323099187333965994803770110787938636994043983837248034866999553;

    uint256 constant IC2x = 7063616195745270811904308918803069427403015788703775904025330060237871929445;
    uint256 constant IC2y = 18424720807911309363093381196375287767072893375494075766205067557166608534440;

    uint256 constant IC3x = 18418797586222067035991720993436454289527094359529685610360875249519151924368;
    uint256 constant IC3y = 32405302241074367251561718504952693967593550524611835810830336668383447024;

    uint256 constant IC4x = 3775981586803290655010305251996492856059724985485973085663875169553143323333;
    uint256 constant IC4y = 12275778758228824724978526828847791841762516354116365174095657568925455572468;

    uint256 constant IC5x = 14444246025360105166836237615102024172879674048116741469380076061969196182439;
    uint256 constant IC5y = 12159701948243560817826484142324748819294707233957078131524212206322787246506;

    uint256 constant IC6x = 18212652661409181442278904093281401853934013458460924809727657426235360801131;
    uint256 constant IC6y = 13699779056537623765605693316807750485656136650910773456669240798299149219824;

    uint256 constant IC7x = 16604367846966049652258117656611400622030441149640333210774738125373413837478;
    uint256 constant IC7y = 1855514909145751799263722723925348721488392005392748711024212550515209569878;

    uint256 constant IC8x = 17480025592314526218675657120009031120251155720872493125191434522224407988382;
    uint256 constant IC8y = 10120161302856625055241377522162201489812657630206137111574645215734425794858;

    uint256 constant IC9x = 2445079191879574026809600407161354657682461308964181837485091671894912949087;
    uint256 constant IC9y = 11141450870351954139590083962119571801609320316600225505665073214317611345208;

    uint256 constant IC10x = 20383712438260803926221634443063961158144553611057967551521665732749986333997;
    uint256 constant IC10y = 6315237470299780231165082054799332016353912279973010409621277058495959541815;

    uint256 constant IC11x = 18421176746817258307643826577002132614405620489979473893972045243409462359070;
    uint256 constant IC11y = 21152146880174528977377685153955639679780236108028376730219774515593569775818;

    uint256 constant IC12x = 18560444557820938900609676405865654378551661503740516245925543084808853749994;
    uint256 constant IC12y = 10952754771222945382462646289037435269057697395531702635448821357698729898975;

    uint256 constant IC13x = 16433118630617948751630075861900980264193785131061692840176291805741542965332;
    uint256 constant IC13y = 6527994616522153860083887966597500673119127439997038624020028674788153342765;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[13] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))

                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))

                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            checkField(calldataload(add(_pubSignals, 320)))

            checkField(calldataload(add(_pubSignals, 352)))

            checkField(calldataload(add(_pubSignals, 384)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
