// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract Counter {
    uint256 public number;

    function increment() external {
        number++;
    }
}
