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
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 16951127126550242556675438530644897111617272926721787340904304628822314519432;
    uint256 constant alphay  = 10536160974842858587610676834478713944986470264709540871290239703556315948907;
    uint256 constant betax1  = 1491224522897895733618116588075318470609412566144781233721058370495871636266;
    uint256 constant betax2  = 17694790541983347883781860820790551605310026027488687804198177961970828565854;
    uint256 constant betay1  = 9508805939184857757018770719130741191471180772208074279490087793737684006933;
    uint256 constant betay2  = 515408405857658715074938790545291181815836896094440105827868650241450067238;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11589754476875468004428882812384186308052281165767913395371718718213526171514;
    uint256 constant deltax2 = 690702184762285991366985009010972260992911362680908705132670155308848751668;
    uint256 constant deltay1 = 3144599958962110452107568062818233773214629645519287738799958330269846432718;
    uint256 constant deltay2 = 10282630683967767206769150940262303975426307098711797126961958110494972772243;

    
    uint256 constant IC0x = 20116767879829685253777053001400214878925735024196314900763642705354921104626;
    uint256 constant IC0y = 9343622837325941267096423821435285775158409184193283832750953758094152865615;
    
    uint256 constant IC1x = 4004555571354014749276849356634248340127009273180076705185287311256106949192;
    uint256 constant IC1y = 18055875423532510059122018454410416733965330396704499359344198985705180805209;
    
    uint256 constant IC2x = 12521474952905561511496237717900248643365052583744837808375291545959409043446;
    uint256 constant IC2y = 10119269130995290694932107899112245152919104017502620118937797780668981936251;
    
    uint256 constant IC3x = 12930464398194510075917359714999439689258379972309662277143582469661469063620;
    uint256 constant IC3y = 18822791414654634433799299462922992988580120881535235916438481319480161530971;
    
    uint256 constant IC4x = 19363868122228723615604752450673588278149476486980289696274345104136252503546;
    uint256 constant IC4y = 12027095613405068779484222330576266245960332676008513725734564005233996630966;
    
    uint256 constant IC5x = 17306411750063110269961617895396360334348935821261460323031422898773681306100;
    uint256 constant IC5y = 7163449038013530045604652329022109307015322199028159835400699697484758421266;
    
    uint256 constant IC6x = 16780562352413914510328855084728168287762664588857934617471287155098801799943;
    uint256 constant IC6y = 20352376894575114022766946721815809110809456125189501620066018208348515331646;
    
    uint256 constant IC7x = 2418137721525469071219401958826923508854362814927142826970032446865129350508;
    uint256 constant IC7y = 13299647594034171773053169994367132720269835547580160219799820683311341712611;
    
    uint256 constant IC8x = 9644894142099230087632077928523689062028566059505286855071705455982384616483;
    uint256 constant IC8y = 12793428388135146600688075114229172242598801405780720832908187761239265203570;
    
    uint256 constant IC9x = 16106816420640981742708994826316018822472976777848144780111827582012024893810;
    uint256 constant IC9y = 9832741909669740359705168741747690568480195966163489798442252701751408575524;
    
    uint256 constant IC10x = 9004054270298373602295487759758709798048188074617597690494387353641839179501;
    uint256 constant IC10y = 784553445146959253950886251442763251976820830490351621793999891875218188191;
    
    uint256 constant IC11x = 1131875520258763563037396607920447074518839812973894710265337934842155406139;
    uint256 constant IC11y = 8533538152801191109361255893454603236654012517458974864036892666205294882910;
    
    uint256 constant IC12x = 17596874234617473106213008838381669881460111814722689419864925877938388325994;
    uint256 constant IC12y = 9830452496608738303884988122237975948787391628224951082183832733087977080381;
    
    uint256 constant IC13x = 9824904776305406005654522024942238437048470044967449859857284071478044534258;
    uint256 constant IC13y = 9171383552083615335658839537167570975220932387819533905701759217345509856892;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[13] calldata _pubSignals) public view returns (bool) {
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
