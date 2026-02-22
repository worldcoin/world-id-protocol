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
    uint256 constant deltax1 = 615804375768004747899180019739425199881572876477593639494210267360260089632;
    uint256 constant deltax2 = 17731721305026924638078260281564326875190773988157261767724093331900259874560;
    uint256 constant deltay1 = 14299621105319571159059178226984787876924418453386800250624342367538826310242;
    uint256 constant deltay2 = 8368376920813525439943668682332439796260234428433137949151998329841922816590;

    
    uint256 constant IC0x = 18240220332579697907104609132438825706340487512076686955056352076719744584398;
    uint256 constant IC0y = 5972632216935418759898403803512083553458108275832488098354884645659014280410;
    
    uint256 constant IC1x = 1927658725952976979005553691373932574498244924384500958907893277538091661376;
    uint256 constant IC1y = 3005472825893443049314754415488525514733237530902745786585256029082451036563;
    
    uint256 constant IC2x = 15868242727720530579678308844155997916566175255987995130170943832937108258840;
    uint256 constant IC2y = 9046519316563864294822794853265947989992185056263736912694345231440957661159;
    
    uint256 constant IC3x = 18837448091040123215825659206879775761288360162949155384786855917081252474428;
    uint256 constant IC3y = 20903053724577750678945073319210731862727977716457080367130019663088184275921;
    
    uint256 constant IC4x = 11893219343683447917439106837719968044058498335218898417941078386315955032771;
    uint256 constant IC4y = 4668132651107682956034805805819502795376195168371080985331896175101309127510;
    
    uint256 constant IC5x = 3976545786981544362318634809568321642751580955136347074027892151021258343711;
    uint256 constant IC5y = 10727246978395479085117984962899646873698169218623443993621925391893968345875;
    
    uint256 constant IC6x = 20710249459583021142669039481324687528045711748300178015896986214560871811052;
    uint256 constant IC6y = 6049924293106655777677636563678287109515989786011954130276824911234051013873;
    
    uint256 constant IC7x = 20016870925188621760586149614478181903727577880476850202359290757287695391383;
    uint256 constant IC7y = 2209127311114565563746178204664519059031287001915696432533565899091721282796;
    
    uint256 constant IC8x = 6004249812960107889805178195941372258410996741727753078607088039371857461482;
    uint256 constant IC8y = 17702834228255345665200619428258096304811845778584236826664490402004872799874;
    
    uint256 constant IC9x = 8337569490279486776128572334328659064988614444330862555933369570061519985548;
    uint256 constant IC9y = 13189430962663742768104551451863372874369513467823616630069115120662502148329;
    
    uint256 constant IC10x = 1846622296759787078690943805804049819090051761930398780983694925351453005034;
    uint256 constant IC10y = 9061024964678748100663309183975490228332293507086339798457177257591926051220;
    
    uint256 constant IC11x = 6923215050406542445107926896393256852324889838471841722145096295572865194264;
    uint256 constant IC11y = 6366738258267829612749506324634816246116611055931912796867889147971925882045;
    
    uint256 constant IC12x = 20367054349146420093681805611402143055256621971624555478454628573422259476634;
    uint256 constant IC12y = 1735521100591698790747044078478902161136843252367975092156700617072645547031;
    
    uint256 constant IC13x = 4893047661599745787419785730422866531585547360252236622431037143797476588593;
    uint256 constant IC13y = 10983770257248223245081381534099306819034043584668227258559255662752291607320;
    
    uint256 constant IC14x = 4098202813780883105565331832034832408033387107398527207455432498056842192568;
    uint256 constant IC14y = 12332836964287898892468885114022743163006939746935171725750310188316970540324;
    
    uint256 constant IC15x = 7906178193972202058471489807448642653066967257373854460306446024607277995237;
    uint256 constant IC15y = 14686929127240673029336935383303057619210835838449428502267592065347197046582;
    
    uint256 constant IC16x = 1044166232070921016316781570054541714406284240980236796686902812162871234673;
    uint256 constant IC16y = 11104913954257832274584628176502941855993037440648755576283018226694233063190;
    
    uint256 constant IC17x = 1455053175430958659870262436547917179327615030705925786946929243986650449086;
    uint256 constant IC17y = 354487540582061840851783522324222921035662811119075833451760814230106067474;
    
    uint256 constant IC18x = 11546325957670279506757441272123647349035950673045120541364084800857571915798;
    uint256 constant IC18y = 6960329187340449707314024680446516174147024066071368647432963066357927920472;
    
    uint256 constant IC19x = 3221281706442870258839979980421333857085813688572604459281354060586703227088;
    uint256 constant IC19y = 6981566535339483682127700453497890479316227613132511184514435263653606080055;
    
    uint256 constant IC20x = 8144301057706245827740986647110878280402791731594302470785647379236515860325;
    uint256 constant IC20y = 10254415153025184631826567298949958540167760769988880563608126416129940263697;
    
    uint256 constant IC21x = 14013045722218027951854314735792988071500410250123300292800631535835145102147;
    uint256 constant IC21y = 15833732976014032223202947952438706977080094431135775715479623608637678113258;
    
    uint256 constant IC22x = 11411952636139768114219534957977181816683868910483664389551163282350035782620;
    uint256 constant IC22y = 4541952696448283342926222784682463091849140235475547643189556175936276717628;
    
    uint256 constant IC23x = 10218678332534967025276919213440595215547871040391764342372016831996751021313;
    uint256 constant IC23y = 4769515606158581434915056058225219888202202809177379187010687884322218656998;
    
    uint256 constant IC24x = 11241423910669010564663034813887634010230662819074250244008954283343652385632;
    uint256 constant IC24y = 5873230876692667397783968458063317125631066966017568935866823958894172305873;
    
    uint256 constant IC25x = 18303803858922218732284290884193113057513219195397842357881001977789800658927;
    uint256 constant IC25y = 9617072141784898131762087748658519694281411143561786510187145434836682787807;
    
    uint256 constant IC26x = 11475265838355136273236448981983077569573217485102669053100555865735854325411;
    uint256 constant IC26y = 6660862310978467576167434350218290701445238433557436791164009795864104129817;
    
    uint256 constant IC27x = 7461226222417942596792472445259095107872369214043537876284259100682539332028;
    uint256 constant IC27y = 21726652992162036112666547409525646319037093651991043244751236751556495417923;
    
    uint256 constant IC28x = 4319127503326038685202388739287213375567042576282681856424498540677490919306;
    uint256 constant IC28y = 12563720682221232453425477482819478125825207413467197788625867457288107305018;
    
    uint256 constant IC29x = 13001820424470625128655283367232019873662106389759362135052384079724924972583;
    uint256 constant IC29y = 8342477652077178532365474486519205820660971707293442168110969663855467346999;
    
    uint256 constant IC30x = 6428906659720072726091009523813240276306532468825030683988955328326696958597;
    uint256 constant IC30y = 4788766395713153626339391137922334159462726127783995986286862825128747967980;
    
    uint256 constant IC31x = 17813711822379231879658940102454411936378046996062889152396945612196164836232;
    uint256 constant IC31y = 18742934775771880286869934449512494997393873484116743800527032957386069853538;
    
    uint256 constant IC32x = 18934274145194700127457718855875459275121526438088025791303472696837428553788;
    uint256 constant IC32y = 19992305434710105353925286067196524739182192573892610181694875398433567285663;
    
    uint256 constant IC33x = 16772360278976516290957844640078735956379241888990144115850408904736113626232;
    uint256 constant IC33y = 1491604127176919122203823424634068549557118199103894457190632450640396126153;
    
    uint256 constant IC34x = 8516625811212156993592540538637440165664951650042960595771262601719758805320;
    uint256 constant IC34y = 14758875315796446255198321488030027954264990994879792103732806552333562357517;
    
    uint256 constant IC35x = 16008169846462152390549099600458835931215117924474501567601077431001291358077;
    uint256 constant IC35y = 3055534019429384781390766226400747386747173667084747734113729187237643616368;
    
    uint256 constant IC36x = 11460975273965026754288913175170851623411431972586467065246515350972311418778;
    uint256 constant IC36y = 10060886577093346627335035179408212781292347965149571884329020755251356922015;
    
    uint256 constant IC37x = 13850781479413453509755258042705587873947437426341944280326724797762341879231;
    uint256 constant IC37y = 18057255320215894210279088184088531716674510618287040958745944988934485131263;
    
    uint256 constant IC38x = 1719658063856134539515583129032406431244798838041966731755873350938660762579;
    uint256 constant IC38y = 6664439542587762452947603266856563300128307156220513152196765589593620420740;
    
    uint256 constant IC39x = 14203471569836992110544921320929454762864906834737080290201645553661284177167;
    uint256 constant IC39y = 19363038451185919474386276481407795409045978172316919207990051764038654754256;
    
    uint256 constant IC40x = 15549233520594625882344784747580842677379774773855788406138435714211253066069;
    uint256 constant IC40y = 10437187490167148768738584638124148682725722835754730497609394451508749125430;
    
    uint256 constant IC41x = 8412677626075764760469754824615018279009560032311344201211213251500732830813;
    uint256 constant IC41y = 3369648991852819298684624384546491774867544175538667756244191112349778633996;
    
    uint256 constant IC42x = 13419122196698268073370683359213737600111019203695456642223808198651294854009;
    uint256 constant IC42y = 1534942589947597113481947234886176839108665132772603746328077722031626852815;
    
    uint256 constant IC43x = 978189601998519432104777299187575023938747672480459124189082271839020599394;
    uint256 constant IC43y = 17929394832325938449241567944989600192601226585266942555279114909061781719708;
    
    uint256 constant IC44x = 19001779697468619500329964324238845881916200878983552427276773850828062796476;
    uint256 constant IC44y = 567677278616665576315609868339765354287168845082514750024165827417854182492;
    
    uint256 constant IC45x = 1402413941665657993350566867752361688504374916534237143035544209870691015528;
    uint256 constant IC45y = 21362274017961771344746443419989343614205142246978616746802500459554118552672;
    
    uint256 constant IC46x = 15426142273645687433098865752243979539410078853197175492256382385366280037330;
    uint256 constant IC46y = 5477526317262372649378679409427389678042804936168061917390568709543348880554;
    
    uint256 constant IC47x = 15839735550238719003039752650458702926711344757228853571246862138002523605266;
    uint256 constant IC47y = 8250427938349118639146075326104136049911628322089793640693625643799098002883;
    
    uint256 constant IC48x = 2856732120892888582770364949882051541753856096985138181895552653049265659166;
    uint256 constant IC48y = 18088897006296486229485899676522376369827720596711032412579092219033874432032;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[48] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))
                
                g1_mulAccC(_pVk, IC43x, IC43y, calldataload(add(pubSignals, 1344)))
                
                g1_mulAccC(_pVk, IC44x, IC44y, calldataload(add(pubSignals, 1376)))
                
                g1_mulAccC(_pVk, IC45x, IC45y, calldataload(add(pubSignals, 1408)))
                
                g1_mulAccC(_pVk, IC46x, IC46y, calldataload(add(pubSignals, 1440)))
                
                g1_mulAccC(_pVk, IC47x, IC47y, calldataload(add(pubSignals, 1472)))
                
                g1_mulAccC(_pVk, IC48x, IC48y, calldataload(add(pubSignals, 1504)))
                

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
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            
            checkField(calldataload(add(_pubSignals, 1376)))
            
            checkField(calldataload(add(_pubSignals, 1408)))
            
            checkField(calldataload(add(_pubSignals, 1440)))
            
            checkField(calldataload(add(_pubSignals, 1472)))
            
            checkField(calldataload(add(_pubSignals, 1504)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
