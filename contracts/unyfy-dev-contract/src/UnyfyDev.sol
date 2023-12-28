// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.13;

import {IPlaceVerifier} from "../interfaces/IPlaceVerifier.sol";
import {ICancelVerifier} from "../interfaces/ICancelVerifier.sol";
import {IFillVerifier} from "../interfaces/IFillVerifier.sol";

contract UnyfyDev {

    event orderPlaced(address indexed pubaddr, uint256 indexed orderhash);

    event orderCancelled(address indexed pubaddr, uint256 indexed orderhash);

    event orderDelete(uint256 indexed orderhash);

    event orderFilled(address indexed pubaddr, uint256 indexed orderhash, uint256[] indexed filledorderhashes);

     function verifyPlaceProof(
        address _addr,
        uint256[2] memory _pA,
        uint256[2][2] memory _pB,
        uint256[2] memory _pC,
        uint256[2] memory _pubSignals
    ) external{

        if(IPlaceVerifier(_addr).verifyProof(_pA, _pB, _pC, _pubSignals)){
            emit orderPlaced(msg.sender, _pubSignals[1]);
        }
        

    }

    function verifyCancelProof(
        address _addr,
        uint256[2] memory _pA,
        uint256[2][2] memory _pB,
        uint256[2] memory _pC,
        uint256[2] memory _pubSignals
    ) external{

        if(ICancelVerifier(_addr).verifyProof(_pA, _pB, _pC, _pubSignals)){
            emit orderCancelled(msg.sender, _pubSignals[1]);
        }
        

    }

    function verifyFillProof(
        address _addr,
        uint256[2] memory _pA,
        uint256[2][2] memory _pB,
        uint256[2] memory _pC,
        uint256[22] memory _pubSignals
    ) external{

        if(IFillVerifier(_addr).verifyProof(_pA, _pB, _pC, _pubSignals)){

            uint256[] memory filledorderhashes = new uint256[](10);
            
            deleteOrderFromTree(_pubSignals[11]);

            for (uint i=12;i<22;i++){
                filledorderhashes[i-12]=_pubSignals[i];
                deleteOrderFromTree(_pubSignals[i]);
            }

            emit orderFilled(msg.sender, _pubSignals[11], filledorderhashes);
        }
        
    }


    function deleteOrderFromTree(uint256 _orderhash) public {
        emit orderDelete(_orderhash);
    }


}
