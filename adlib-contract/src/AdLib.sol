// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract AdLib {
    address public pubaddr; // the public address of the sender 
    uint256 public orderhash; 

    event orderPlaced(address pubaddr, uint256 orderhash);

    event orderCancelled(address pubaddr, uint256 orderhash);

    event orderGetCrossed(address pubaddr, uint256 orderhash);


    function place(uint256 _orderhash) public {
        pubaddr = address(msg.sender);
        orderhash = _orderhash;
        emit orderCancelled(pubaddr, orderhash);
    }

    function cancel(uint256 _orderhash) public {
        pubaddr = address(msg.sender);
        orderhash = _orderhash;
        emit orderCancelled(pubaddr, orderhash);
    }

    function getCrossed(uint256 _orderhash) public {
        pubaddr = address(msg.sender);
        orderhash = _orderhash;
        emit orderGetCrossed(pubaddr, orderhash);
    }

   /* function increment() public {
        number++;
    } */
}
