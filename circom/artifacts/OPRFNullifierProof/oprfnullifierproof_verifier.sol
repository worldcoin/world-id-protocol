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
    uint256 constant alphax  = 16428432848801857252194528405604668803277877773566238944394625302971855135431;
    uint256 constant alphay  = 16846502678714586896801519656441059708016666274385668027902869494772365009666;
    uint256 constant betax1  = 3182164110458002340215786955198810119980427837186618912744689678939861918171;
    uint256 constant betax2  = 16348171800823588416173124589066524623406261996681292662100840445103873053252;
    uint256 constant betay1  = 4920802715848186258981584729175884379674325733638798907835771393452862684714;
    uint256 constant betay2  = 19687132236965066906216944365591810874384658708175106803089633851114028275753;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 18276312260462464301786116071270072837639658096470751911770498446911342110155;
    uint256 constant deltax2 = 6198252822679132168335183900719774479358254696910202838593113610721221509433;
    uint256 constant deltay1 = 20926887412577696257791489476997380047410196433686510808784841941925246413039;
    uint256 constant deltay2 = 11720331797331725206364446556575708597556769708423400714806918867493624464462;

    
    uint256 constant IC0x = 12707154156956426876205421069762951430587922082374452196061203590996603122898;
    uint256 constant IC0y = 11988051227811702937081487499189950268834685612677837953086727928714085898782;
    
    uint256 constant IC1x = 18130866512109999048944103382025396564839971558080553194336478570622460551663;
    uint256 constant IC1y = 10917889356338454322413369923730513779104527783498250513211494202730669497355;
    
    uint256 constant IC2x = 10731668278765206671822666331775393605226701497875783152744053599673737484563;
    uint256 constant IC2y = 606130650215070645556372737058097563845461830266664204296380386472851271064;
    
    uint256 constant IC3x = 7891367436548121483737548370166014724156933560245880131217604852723541599039;
    uint256 constant IC3y = 4157478755686502527805879927904580889637436179713881901010787535484528032972;
    
    uint256 constant IC4x = 3373978306004882156286995429766013266564958098405135677231188293347044763032;
    uint256 constant IC4y = 12962051492588420352880494754147536539495746711369409596561829631910232084060;
    
    uint256 constant IC5x = 2200268951285539566855820779868880112679290606319451528102121918046079234595;
    uint256 constant IC5y = 8476116822948355055307802895990098305123783126262533306459408650921472681502;
    
    uint256 constant IC6x = 555844460264497701134478875915156216851837708786555089341214244707737387913;
    uint256 constant IC6y = 2353302559916998643178355210712781061605437038299270001070341375677348625332;
    
    uint256 constant IC7x = 10501997153579162514954308445252704336227962138111416309604124217697291910798;
    uint256 constant IC7y = 18044988622213670783915153901298923726240404002617862955375682341418427866538;
    
    uint256 constant IC8x = 1888455001806267340733075626004133723546503504091872787113656311144830289310;
    uint256 constant IC8y = 406996656128495100166576166339621844969673303503310199152117374926616505110;
    
    uint256 constant IC9x = 17340575978191110770479268143212865737348453019776150783384376185309886147471;
    uint256 constant IC9y = 17506278945400349149075539600742500193555940659491693707958852985198491614023;
    
    uint256 constant IC10x = 10294885580137833426781046193094363086413561961612707928134642858760302829012;
    uint256 constant IC10y = 540605552482323047416300231228748773541700721077534860535925077248936701640;
    
    uint256 constant IC11x = 14097714348605682268199408610137506759608790215454573329754584077607550463296;
    uint256 constant IC11y = 14314209957942027099186218356215985969619921120822449148608808720036104884978;
    
    uint256 constant IC12x = 13861794529879157596599909112149632156774118530563570014217711280554564353962;
    uint256 constant IC12y = 10923687406641654062634317199809722315729907668489021389943203237216572875799;
    
    uint256 constant IC13x = 11063492112917510642498508742534757036275498930337887964520624700772755763611;
    uint256 constant IC13y = 1080275527637065076606546806103721847770274707050820832707341448196359219159;
    
    uint256 constant IC14x = 8305096101809936022610499570545191179240488941163083615993088787122916816091;
    uint256 constant IC14y = 4051893384402757580214249940740969478380163418551517204511272447676198016741;
    
    uint256 constant IC15x = 15050022005068262203482113579861697100287411162150564670762660051133717708560;
    uint256 constant IC15y = 12211338396471543847598704140623873930396235403465327507870621016558207727031;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[15] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                

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
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
