import { ethers } from 'ethers'
import { env } from '../config/env.js'
import { logger } from './logger.js'
import { db } from './db.js'

const ABI = [
    'function anchor(bytes32 hash) external',
    'event Anchored(bytes32 indexed hash, uint256 indexed timestamp, address indexed sender)',
]

let _provider: ethers.JsonRpcProvider | null = null
let _wallet: ethers.Wallet | null = null
let _contract: ethers.Contract | null = null

function ethersInstances() {
    if (!_provider || !_wallet || !_contract) {
        _provider = new ethers.JsonRpcProvider(env.POLYGON_RPC_URL)
        _wallet = new ethers.Wallet(env.POLYGON_PRIVATE_KEY, _provider)
        _contract = new ethers.Contract(env.POLYGON_ANCHOR_CONTRACT, ABI, _wallet)
    }
    return { provider: _provider, wallet: _wallet, contract: _contract }
}

// ── WALLET BALANCE ────────────────────────────────────────────
export async function checkAnchorWalletBalance() {
    const { provider, wallet } = ethersInstances()
    const balance = await provider.getBalance(wallet.address)
    const balanceMatic = ethers.formatEther(balance)
    return { address: wallet.address, balanceMatic, isSufficient: parseFloat(balanceMatic) >= env.POLYGON_MIN_BALANCE }
}

// ── ANCHOR ────────────────────────────────────────────────────
export interface AnchorResult {
    txHash: string
    blockNumber: number
    gasUsed: string
    anchoredAt: Date
}

export async function anchorHash(credentialId: string, sha256Hash: string, attempt = 1): Promise<AnchorResult> {
    const { contract } = ethersInstances()
    const hashBytes = '0x' + sha256Hash

    logger.info({ credentialId, sha256Hash, attempt }, 'blockchain: anchoring')

    try {
        const fn = contract.getFunction('anchor')
        const gasEstimate = await fn.estimateGas(hashBytes)
        const gasLimit = (gasEstimate * 130n) / 100n

        const tx: ethers.TransactionResponse = await fn(hashBytes, { gasLimit })
        logger.info({ credentialId, txHash: tx.hash }, 'blockchain: tx submitted')

        const receipt = await tx.wait(2)
        if (!receipt || receipt.status !== 1) throw new Error(`Tx failed: ${tx.hash}`)

        const result: AnchorResult = {
            txHash: receipt.hash,
            blockNumber: receipt.blockNumber,
            gasUsed: receipt.gasUsed.toString(),
            anchoredAt: new Date(),
        }

        await db.credential.update({
            where: { id: credentialId },
            data: { txHash: result.txHash, blockNumber: BigInt(result.blockNumber), anchoredAt: result.anchoredAt, blockchainNetwork: 'polygon-mainnet' },
        })

        logger.info({ credentialId, ...result }, 'blockchain: confirmed')
        return result

    } catch (err) {
        logger.error({ credentialId, attempt, err }, 'blockchain: failed')
        if (attempt < 3) {
            await new Promise(r => setTimeout(r, Math.pow(2, attempt) * 1000))
            return anchorHash(credentialId, sha256Hash, attempt + 1)
        }
        throw err
    }
}

// ── VERIFY ON-CHAIN ───────────────────────────────────────────
export async function verifyHashOnChain(txHash: string, expectedHash: string): Promise<boolean> {
    try {
        const { provider } = ethersInstances()
        const receipt = await provider.getTransactionReceipt(txHash)
        if (!receipt) return false

        const iface = new ethers.Interface(ABI)
        for (const log of receipt.logs) {
            try {
                const parsed = iface.parseLog(log)
                if (parsed?.name === 'Anchored') {
                    return (parsed.args[0] as string).toLowerCase() === ('0x' + expectedHash).toLowerCase()
                }
            } catch { /* skip */ }
        }
        return false
    } catch (err) {
        logger.error({ txHash, err }, 'blockchain: verify failed')
        return false
    }
}

/*
  SOLIDITY CONTRACT (deploy once, put address in POLYGON_ANCHOR_CONTRACT):

  // SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;

  contract VeriSureAnchor {
    event Anchored(bytes32 indexed hash, uint256 indexed timestamp, address indexed sender);
    mapping(bytes32 => uint256) public anchors;

    function anchor(bytes32 hash) external {
      require(anchors[hash] == 0, "Already anchored");
      anchors[hash] = block.timestamp;
      emit Anchored(hash, block.timestamp, msg.sender);
    }

    function isAnchored(bytes32 hash) external view returns (bool, uint256) {
      uint256 ts = anchors[hash];
      return (ts != 0, ts);
    }
  }
*/