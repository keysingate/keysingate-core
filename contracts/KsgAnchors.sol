// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// The last anchor of every container, for `light` and `bare` on Base Sepolia
/// (owner's decisions 14.10: minimal anchors for `light`, all anchors of
/// `bare` and `light` on Base Sepolia).
///
/// One rule does the work: an anchor must continue the container's last one.
/// Two copies of a container share their last anchor at the moment of copying;
/// the first to anchor moves the head, and the second is refused here — that
/// refusal is how a copy, or a rolled-back file, learns what it is. A memo
/// chain cannot refuse anything; a contract can.
///
/// Who may write: the account that put the first anchor, until it hands the
/// container over. A stranger cannot push a head forward and so shut the
/// owner out.
///
/// Kept minimal on purpose (owner's principle of a minimal surface): no
/// owner of the contract, no upgrade, no fees, no tokens.
contract KsgAnchors {
    struct Head {
        bytes32 last;
        address writer;
        uint64 count;
    }

    mapping(bytes32 => Head) private heads;

    event Anchored(bytes32 indexed container, bytes32 prev, bytes32 next, uint64 count, address writer);
    event HandedOver(bytes32 indexed container, address from, address to);
    event Noted(bytes32 indexed kind, address indexed sender, bytes data);

    error ZeroAnchor();
    error NotWriter(address writer);
    error StalePredecessor(bytes32 head, bytes32 presented);

    /// Puts `next` after `prev` as the container's last anchor.
    function anchor(bytes32 container, bytes32 prev, bytes32 next) external {
        if (next == bytes32(0)) revert ZeroAnchor();
        Head storage h = heads[container];
        if (h.writer == address(0)) {
            if (prev != bytes32(0)) revert StalePredecessor(bytes32(0), prev);
            h.writer = msg.sender;
        } else {
            if (msg.sender != h.writer) revert NotWriter(h.writer);
            if (prev != h.last) revert StalePredecessor(h.last, prev);
        }
        h.last = next;
        h.count += 1;
        emit Anchored(container, prev, next, h.count, msg.sender);
    }

    /// The writer hands the container to another account (a transfer of
    /// rights).
    function handOver(bytes32 container, address to) external {
        Head storage h = heads[container];
        if (msg.sender != h.writer || to == address(0)) revert NotWriter(h.writer);
        emit HandedOver(container, h.writer, to);
        h.writer = to;
    }

    /// A note on the chain, kept in the log only: the issuance anchor of a
    /// `bare` (`kind` = keccak("ksg:ia:v1"), `data` = its sealed table). No
    /// state, no rule — the issuers read the notes of a kind back by its topic.
    function note(bytes32 kind, bytes calldata data) external {
        emit Noted(kind, msg.sender, data);
    }

    /// The container's last anchor, its writer and how many anchors it has.
    function head(bytes32 container) external view returns (bytes32 last, address writer, uint64 count) {
        Head storage h = heads[container];
        return (h.last, h.writer, h.count);
    }
}
