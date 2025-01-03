pragma solidity ^0.8.0;

contract CredentialHashes {
    mapping(address => string) public hashes;

    function storeHash(string memory hash) public {
        hashes[msg.sender] = hash;
    }

    function getHash() public view returns (string memory) {
        return hashes[msg.sender];
    }
}
