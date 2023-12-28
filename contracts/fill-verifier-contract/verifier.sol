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

contract FillVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 4118358589336846826240488041949605352469513290883358537524867007225024990430;
    uint256 constant alphay  = 15275561144379853963452625394664723363600294302894688791573761300486042649313;
    uint256 constant betax1  = 14438601754819638058385103892151341472435795725780771441995174698564765583247;
    uint256 constant betax2  = 16089165693874702872113608514049857775486984003541265395926153179576981391897;
    uint256 constant betay1  = 6358094984920194731347091300327168440692107370788609951254928639512479875856;
    uint256 constant betay2  = 11820691273830720329496625291790784472654339388823210706998649228469747485456;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 232359313771953803540521518565431059247381247062020737202692612271541578255;
    uint256 constant deltax2 = 16239829046216956884356690810880664118732431250068411036652961730984901365979;
    uint256 constant deltay1 = 13597197076908928057603779500198100210450056051037293149421420139043383659506;
    uint256 constant deltay2 = 12491269625140340362195520397731435371679923055468506725812124108197651381244;

    
    uint256 constant IC0x = 13135192694415836847534964798526092787849747648825293154728063498293327468023;
    uint256 constant IC0y = 6386113473704154549893569789943501676828534937112543407519800950677817068550;
    
    uint256 constant IC1x = 3624892346010052560004216875300939250621372004491842723963114441234116613026;
    uint256 constant IC1y = 12016191615619219831092457032888281631242046313407287456109225025775755260572;
    
    uint256 constant IC2x = 20964062249226590079730173112999105899763384451006707308195117867744732924721;
    uint256 constant IC2y = 16180290853709702587627352822201153181923684490635237880209832599028066174840;
    
    uint256 constant IC3x = 12425579969962986071698571634888880653081281382803121704586956864898510805125;
    uint256 constant IC3y = 16539362587393390296204669251506795251834184328470019196582292864672831559542;
    
    uint256 constant IC4x = 10019680763285662221221778548540049452179121611048896193407865287036657379883;
    uint256 constant IC4y = 20996368007999735775626593435908918859856975528964476945191458216695604667838;
    
    uint256 constant IC5x = 8547744264232608052759462191155563944837911660427971431388151342751549762655;
    uint256 constant IC5y = 18121365752968338990844332784983179241576747424455877455179581172710674159742;
    
    uint256 constant IC6x = 1964570774988815778695808152222156716092254440608655242571621417292787999280;
    uint256 constant IC6y = 17216649596445537661994659756971155465228388040896524790097720794992122828240;
    
    uint256 constant IC7x = 4395813797550296212017827949661866788700379666345026198049867962061991992155;
    uint256 constant IC7y = 8044402395272189417602971512667051733517314417423347907226806414102915272917;
    
    uint256 constant IC8x = 8187279547785477986165373315179419736087015449164879964182852345766129719389;
    uint256 constant IC8y = 16101842516448401842315065624752021414915997655626246739648647973872862538908;
    
    uint256 constant IC9x = 12649018863920811683853033612561777819285198114300501717324888880263749133984;
    uint256 constant IC9y = 9708158263465765471251226475538101228996624163318984035259988886953970342754;
    
    uint256 constant IC10x = 8773226726956891175719743864417387839555853360122221910603413480130587788802;
    uint256 constant IC10y = 4844197452580987354225172248294641679299752282018906944912343118688983337775;
    
    uint256 constant IC11x = 16263923444701705057245689479845845065554036281627249550079879850196945366639;
    uint256 constant IC11y = 5758701732788407477018459705125738915057578732640693392437070542724067127926;
    
    uint256 constant IC12x = 14086813589445618146141112821181159849242314445300722275600657784729104124383;
    uint256 constant IC12y = 19250086248103483472750581781175959126905308481334129648672100181946256357075;
    
    uint256 constant IC13x = 5168777934765876642258199174760949156389437358697233556685942587078636655516;
    uint256 constant IC13y = 550295388524173414630296408546265108483845538879976953637543672719621249235;
    
    uint256 constant IC14x = 3866773267314826845995821820281207732929815617962052455619824924024444793773;
    uint256 constant IC14y = 20991302937085021192024087519311163222677527006850285542114782706870817138360;
    
    uint256 constant IC15x = 18500268421426442748067379925410176731686045327847342423948474727276331152179;
    uint256 constant IC15y = 33393304050542907024321963275606215438374670732665935976604628172641173505;
    
    uint256 constant IC16x = 21035514166656208483735621342704324071725446771726781047266455060796853252640;
    uint256 constant IC16y = 3786663526952312449533417065756445092031991867160814421413463436544252538290;
    
    uint256 constant IC17x = 17890675347402699917333685693026579149728670945055737091384105772317066840963;
    uint256 constant IC17y = 21146852805004606032058191332490520354569790107914977686951308225816348913326;
    
    uint256 constant IC18x = 3858130589075080072175492080267427231470605121027479045591327351943284671374;
    uint256 constant IC18y = 10052974870400889143962093797546805966369398403482441179547120220072014434761;
    
    uint256 constant IC19x = 6572963463085873003735669525475041175412236057798346733135106213437755210776;
    uint256 constant IC19y = 20825407453933048439882037405801971730743313250473230466906853879515944182045;
    
    uint256 constant IC20x = 2815249728577274729982800419467823886614036558836067328054725251338405183103;
    uint256 constant IC20y = 21783064215431978779607635369494111403436216734258023179528259049114699633006;
    
    uint256 constant IC21x = 16361516436078210370281599956764945772379637715843701819892518161775293646827;
    uint256 constant IC21y = 8834916509962451888331210906261730801156091740389682899187538177132902887301;
    
    uint256 constant IC22x = 11005734509700257206283397238139963178690888003530204293062252579173982533742;
    uint256 constant IC22y = 10913198026792022999642102070279637176194593922731603263975110083973855919179;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[22] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
