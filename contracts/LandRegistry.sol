// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LandRegistry {
    struct Land {
        string ownerName;
        string location;
        uint area;
        address ownerAddress;
    }

    uint public landCount = 0;
    mapping(uint => Land) public lands;

    event LandRegistered(uint id, address indexed owner);

    function registerLand(string memory _ownerName, string memory _location, uint _area) public {
        landCount++;
        lands[landCount] = Land(_ownerName, _location, _area, msg.sender);
        emit LandRegistered(landCount, msg.sender);
    }

    function getLand(uint _id) public view returns (string memory, string memory, uint, address) {
        require(_id > 0 && _id <= landCount, "Land ID invalid");
        Land memory land = lands[_id];
        return (land.ownerName, land.location, land.area, land.ownerAddress);
    }

    function isOwner(uint _id) public view returns (bool) {
        require(_id > 0 && _id <= landCount, "Invalid land ID");
        return lands[_id].ownerAddress == msg.sender;
    }
}
