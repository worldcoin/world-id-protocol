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
    uint256 constant deltax1 = 12196030332664696446007716810492187748033801714662465903887216347435084690561;
    uint256 constant deltax2 = 11545017281187878394282580019815313295239511214899595953787455665386959124455;
    uint256 constant deltay1 = 10193065738088138535942081606489088212843198084981112976006178232275296867311;
    uint256 constant deltay2 = 3607214296249402343577308862979323145255902668921535718771418172034248799655;

    
    uint256 constant IC0x = 19433609082259951117817553065795295684788638895696550457768126840971688288119;
    uint256 constant IC0y = 4803948923578208869609218032301050093703416004608302992757342864818195614028;
    
    uint256 constant IC1x = 18724653980327473187989178757789310788615894844383423580742813937620339255721;
    uint256 constant IC1y = 1357598423697425021150937404051499597956929828740286936236490625651561640971;
    
    uint256 constant IC2x = 1976184284707498494050887800382420751469754937504686510774064591302881592298;
    uint256 constant IC2y = 6029798073048419755421265026523523136056169836532217877198954722425693236942;
    
    uint256 constant IC3x = 6398105807844693557081175820401315375359522752196579871056239910907168983333;
    uint256 constant IC3y = 18377949836094283137294292755980253930667233217110346645053802817832807235682;
    
    uint256 constant IC4x = 3297545187919676023866497736952336736632780600911345235884838259310677074650;
    uint256 constant IC4y = 11063141888094264269031735726671574734012145531659733080646028135811462987188;
    
    uint256 constant IC5x = 15267544553975671391517783009174195667850065685467148187789250953653236599717;
    uint256 constant IC5y = 8416038689889969221462871754855339622826422313831976049186982226389757087220;
    
    uint256 constant IC6x = 2959526176167649246250281076609817874251496003032132115519385438568874365638;
    uint256 constant IC6y = 1327865670833936314342705803481606607648756086423464508007219732078901770644;
    
    uint256 constant IC7x = 15136200406842390452406894650438454242337663293644169742969423427985833979167;
    uint256 constant IC7y = 16553568243102908552883161369337189806045129065220427367033691494785792437716;
    
    uint256 constant IC8x = 15061151157361388402167945124480532876336479502016073508762093285040699672246;
    uint256 constant IC8y = 4853124076797449063186503394029882528893911711763809753120623196892805455958;
    
    uint256 constant IC9x = 158380092359935021287096751583319080896614836571044035997610069888509141262;
    uint256 constant IC9y = 526275539689662721039326131922436001494772244154476271593974523421343833854;
    
    uint256 constant IC10x = 8532461139245335006900292175419507630971068722434655580132141302102677524514;
    uint256 constant IC10y = 4648130039941839813514294060716600760996414344291276201722732778535626251721;
    
    uint256 constant IC11x = 14171922798210949778974726884282687585709061638595430398443251970955474277015;
    uint256 constant IC11y = 13075653123576814590072707472646284544628592358377531674806042457813003589452;
    
    uint256 constant IC12x = 14985289508378150323876488737742454728048399902658433495503190860601136368983;
    uint256 constant IC12y = 13525093242699422123837714520335125300206710700678209496640635185725491562084;
    
    uint256 constant IC13x = 19642872901245694499664137696158924433520687210858180155047900407629872165611;
    uint256 constant IC13y = 8757753550212581607428512434289630631394134583775815670406875792611014632924;
    
    uint256 constant IC14x = 14615165539572655773009781545659482958271717804448537670421578832414790915638;
    uint256 constant IC14y = 20804899980339582298439954116346745130018405775279295795172585940917823564326;
    
    uint256 constant IC15x = 4333165301208093738798433973498381802448679086449820930926376380209129574821;
    uint256 constant IC15y = 5384748330975063717195143812057564623719497294939760778519696557641727285990;
    
    uint256 constant IC16x = 12413993471230511596061036306981990006997545275397916155097582246914104340888;
    uint256 constant IC16y = 3593466700528073686252200103291516197687569931539945189749891334674667818483;
    
    uint256 constant IC17x = 3177572148252597682504277874578189693930403283654213839854718289815486931747;
    uint256 constant IC17y = 19667815907862348549695070721753796161062712238262892791928996318918954806547;
    
    uint256 constant IC18x = 18767343356234437610979422290173590973478655810733974228191267129433259300578;
    uint256 constant IC18y = 17261374035566884270508402180319548356299800173521385178071109657934621258631;
    
    uint256 constant IC19x = 93121035699115235367661864907329377027018567948381862123212679493630837275;
    uint256 constant IC19y = 17403921761278698269241028741367712331438818676676738426621463379827266161651;
    
    uint256 constant IC20x = 6127011155463948689972752609806772929096115529632827745148420819265539602571;
    uint256 constant IC20y = 14749457455320364693510824548919189716022420914662197442395526448450852310441;
    
    uint256 constant IC21x = 20704977433491625399742832846467939394084632307180466508695790511009924521476;
    uint256 constant IC21y = 16926811227442642613292926603378923386453637986171800398600721089167198620517;
    
    uint256 constant IC22x = 18764812346612609838338047318099864623931176719276229427285803021418878026755;
    uint256 constant IC22y = 18662346494703920608049516786888221867620983760893964700937646581274188016066;
    
    uint256 constant IC23x = 10683851279325490686116565869508759603974625117463474912501375970932941134816;
    uint256 constant IC23y = 7947963640037412720568977830846294389261035122796752100909296635427982078890;
    
    uint256 constant IC24x = 19989364267268964417173397855610363741665614232285530444504756617297905213153;
    uint256 constant IC24y = 9399903362581275185126347319010559497288148711093113887049390835669339615567;
    
    uint256 constant IC25x = 15470419004400456922503796517028352931388828945044991542944101440750520984521;
    uint256 constant IC25y = 8090977179192268257154728432900920512228757486279498933628030708575180809607;
    
    uint256 constant IC26x = 19284902829626243307676318372730957651800861315078686348829829504224397068113;
    uint256 constant IC26y = 9698939452761060657159245867927170194174749364675554480896130323055157382973;
    
    uint256 constant IC27x = 8395139078845508063750389485982802265426161650164750179593229447333388851871;
    uint256 constant IC27y = 7038518811434349425598693553068741309052921402418879349665415410426124742466;
    
    uint256 constant IC28x = 17087868113578169087409365121482475918863039919062947928683999127468044354658;
    uint256 constant IC28y = 366392458522342555317673401258268028512111770075141456174254006107504329265;
    
    uint256 constant IC29x = 6917316535047277861483456390441851801462003130637159113120029996026157157970;
    uint256 constant IC29y = 14108092360010711133266757764977576994526077155820577999150769158182844248602;
    
    uint256 constant IC30x = 13769524201896346724684203084270124844121256815890289448321977445013577311423;
    uint256 constant IC30y = 2398125464985601516495034994684135927815084263047045030162363500828815827722;
    
    uint256 constant IC31x = 8394147279868434013714327230997134486536588055494062728790362210934784143230;
    uint256 constant IC31y = 17295167306460889490405342350233101172899062828850777718088439545021463552380;
    
    uint256 constant IC32x = 4689950336946934730875167548716972730985653888693385496026157873120068247702;
    uint256 constant IC32y = 14541981952393776950100161146004707591699971122650774287760732701376465501282;
    
    uint256 constant IC33x = 8174118715305354483756480444069741750681454988801758671158471412803475409370;
    uint256 constant IC33y = 13389015689264648803707253189882930621996898727522749158454204914992479325408;
    
    uint256 constant IC34x = 6857059956421721895801657164130786204232976865358212550510294688362824689046;
    uint256 constant IC34y = 10456177055871462357893957020717838972458169034584349211270976418401170722581;
    
    uint256 constant IC35x = 16438904947882730121934567631687766025300901155000200869089222176985209964988;
    uint256 constant IC35y = 13479914555961902045103809151070972530128261376038586154011896440915403279873;
    
    uint256 constant IC36x = 11915481117728208222148436307856860132735871303019864019180323408950019599983;
    uint256 constant IC36y = 5405455918091423093494395801613013198670697154896976249468345275389190778735;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[36] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                

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
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
