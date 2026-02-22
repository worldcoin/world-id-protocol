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
    uint256 constant deltax1 = 3100113659196176915735527845030654407252192897430006763072419679217151677894;
    uint256 constant deltax2 = 20416147618672327181496314377762177756411542558225721685822921251920749822510;
    uint256 constant deltay1 = 12117128391780660995096967478153557508975500089682604734620799205666430277846;
    uint256 constant deltay2 = 7941155771880539042959022507666340439306260381839768833385228061379353071983;

    
    uint256 constant IC0x = 4636912401289605430186595384614419265192391206871322984141831113370769651397;
    uint256 constant IC0y = 19235305027285712399006668250445412095253165855504249073268733925194962962698;
    
    uint256 constant IC1x = 12567966246863362928893693245208042544358399479312222894410396019153048633631;
    uint256 constant IC1y = 6479958966384227148449518586233480486236295384467961724571928119678976208679;
    
    uint256 constant IC2x = 20141779122227635546973762294961596211466040675864165982645436005717841637917;
    uint256 constant IC2y = 11913325711955287316660204251386150480148597099702119944474818256999130448213;
    
    uint256 constant IC3x = 10647009886713838571737819789398074803510496762085250884601257054088162467356;
    uint256 constant IC3y = 15312120416179538903743034194275886778260551424200036711046599726113366789379;
    
    uint256 constant IC4x = 18887669456047619589196644743904228849343405178318149107782638183593789951359;
    uint256 constant IC4y = 4696154771093604181938009941471817698915492426162345619946491866609096246694;
    
    uint256 constant IC5x = 329805360437195294420685272060011903799213973595209385193002653006976170360;
    uint256 constant IC5y = 6978478676186466867939911344397044005422196146450331532487434791373830710751;
    
    uint256 constant IC6x = 13885798091403025597227567975541012313528838913954103276772189949917171258105;
    uint256 constant IC6y = 4909727904204681036952993460908561753131750576694252341515780909969756734356;
    
    uint256 constant IC7x = 11980932207507748968618834950659226228373468867088971402512520040864211356846;
    uint256 constant IC7y = 5254256294647295122623587357217889292622871451017291291626565083420328843135;
    
    uint256 constant IC8x = 14628904955164262167573415426310236583199322615650257284542226558588444450862;
    uint256 constant IC8y = 17107916571222053712571970710669377335795917129593591723503392984972630139292;
    
    uint256 constant IC9x = 4407166230559029971127174115330141658925851948025565790517731322950806806448;
    uint256 constant IC9y = 2607893106447829894741079378460182571922634994150859006992349496379939060133;
    
    uint256 constant IC10x = 21512324140035715295556155912454981620677307979244657008222468311226183098772;
    uint256 constant IC10y = 12345141329360439086791004351017152629032447666267787849504309567876650113145;
    
    uint256 constant IC11x = 13962877409661548130636101794622299433719881797126008984912024951679374264676;
    uint256 constant IC11y = 13464302345357358791971133394228968491774725275550907238784813425163659246291;
    
    uint256 constant IC12x = 3432243814266620638290672324840742184860074946581251527379166862188109468136;
    uint256 constant IC12y = 8837987680903705416670814226579566557862796025304482094837991567727772178954;
    
    uint256 constant IC13x = 7250818034766689678782365649610392684627918070304296139126608247844654733674;
    uint256 constant IC13y = 4289877655588061983235437588707444384804147237165686479809067768185996307429;
    
    uint256 constant IC14x = 19290341701807051171472609516162613260788622136636085063938443973121986343590;
    uint256 constant IC14y = 2447792099859633311508432580374154093420166796028934577728533830582141324792;
    
    uint256 constant IC15x = 2389036754436815233044631922463681237315806071620086028202493054727244558997;
    uint256 constant IC15y = 15076047271850229808081157550857128177714825832705941541825254705438283226578;
    
    uint256 constant IC16x = 6168023929013100848918573722531818754472201530427695531090079167283115289351;
    uint256 constant IC16y = 17502373406441179558544046750634417193166514711092186065189561592472971333487;
    
    uint256 constant IC17x = 6713547916927240459044651275143568009191583425711151742453562762972915678000;
    uint256 constant IC17y = 18673750271228129977472894981215505985156840714661830344096391208584640559795;
    
    uint256 constant IC18x = 117838262660668150969573538417003081899496768333347898599255766786074191635;
    uint256 constant IC18y = 10568291107415909301273035637496153916187750471477180895918015241206237253110;
    
    uint256 constant IC19x = 11611537214234449183906276162687132657491953051111391168791284897446933533143;
    uint256 constant IC19y = 14249091826185252524632638980988188414328109285083313364624768255388682412212;
    
    uint256 constant IC20x = 4302243175472347634515978234493548131544957637055842980108591398084859839046;
    uint256 constant IC20y = 17825091678370408244431278192855617904833457092075008817095450759668077332230;
    
    uint256 constant IC21x = 12927683827953833268997726198397804550177874384857611371517569845454169641718;
    uint256 constant IC21y = 8385030926956632182369274270363564031833340008972901563736525453338945284291;
    
    uint256 constant IC22x = 1148212594231580329794968855885163219814306221672746703206095118190309617769;
    uint256 constant IC22y = 14115368107921781383729314757511041162894535219871639350034309172422341487129;
    
    uint256 constant IC23x = 18487440200621568630853182609687424221724448146641916796103209423471829424547;
    uint256 constant IC23y = 8078275538103025363224031941058767966375821932518360737881859623997192944024;
    
    uint256 constant IC24x = 7878132704712584228029376093805588170988939866713089134484959988888978020138;
    uint256 constant IC24y = 10228856106359042766239948865235436171959670512001809141089064943669299620258;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[24] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                

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
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
