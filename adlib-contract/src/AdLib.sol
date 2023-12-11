// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract AdLib {

    event orderPlaced(address indexed pubaddr, uint256 indexed orderhash);

    event orderCancelled(address indexed pubaddr, uint256 indexed orderhash);

    event orderGetCrossed(address indexed pubaddr, uint256 indexed orderhash);

    event orderFilled(address indexed pubaddr, uint256 indexed orderhash, uint256[] indexed filledorderhashes);


    function place(uint256 _orderhash) public {
        emit orderPlaced(msg.sender, _orderhash);
    }

    function cancel(uint256 _orderhash) public {
        emit orderCancelled(msg.sender, _orderhash);
    }

    function getCrossed(uint256 _orderhash) public {
        emit orderGetCrossed(msg.sender, _orderhash);
    }

    function fill(uint256 _orderhash, uint256[] memory _filledorderhashes) public {
        emit orderFilled(msg.sender, _orderhash, _filledorderhashes);
    }

}
