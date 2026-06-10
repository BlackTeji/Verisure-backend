// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

/// ═══════════════════════════════════════════════════════════════════
/// VeriSureAnchor
/// ═══════════════════════════════════════════════════════════════════

contract VeriSureAnchor {
    // ── STORAGE ──────────────────────────────────────────────────────

    mapping(bytes32 => uint256) private _anchoredAt;

    // ── EVENTS ───────────────────────────────────────────────────────

    event Anchored(
        bytes32 indexed hash,
        uint256 indexed timestamp,
        address indexed sender
    );

    // ── ANCHOR ───────────────────────────────────────────────────────

    function anchor(bytes32 hash) external {
        require(hash != bytes32(0), "Empty hash");
        require(_anchoredAt[hash] == 0, "Already anchored");

        _anchoredAt[hash] = block.timestamp;

        emit Anchored(hash, block.timestamp, msg.sender);
    }

    // ── QUERY ────────────────────────────────────────────────────────

    function isAnchored(bytes32 hash) external view returns (bool, uint256) {
        uint256 ts = _anchoredAt[hash];
        return (ts != 0, ts);
    }
}
