import { ethers } from 'ethers'
import { env } from '../config/env.js'
import { logger } from './logger.js'
import { db } from './db.js'

// ── CONTRACT ABI ──────────────────────────────────────────────
// Matches VeriSureAnchor.sol exactly.
// The anchor() function takes a bytes32 hash and emits Anchored.
const ABI = [
    'function anchor(bytes32 hash) external',
    'function isAnchored(bytes32 hash) external view returns (bool, uint256)',
    'event Anchored(bytes32 indexed hash, uint256 indexed timestamp, address indexed sender)',
]

// ── SINGLETON ─────────────────────────────────────────────────
// Lazily initialised and reset on any provider/network failure.
// Singleton is intentional — avoids opening a new WSS/HTTPS connection
// per job when the anchor worker processes credentials concurrently.
let _provider: ethers.JsonRpcProvider | null = null
let _wallet: ethers.Wallet | null = null
let _contract: ethers.Contract | null = null

function resetInstances() {
    _provider = null
    _wallet = null
    _contract = null
}

function getInstances() {
    if (!_provider || !_wallet || !_contract) {
        if (!env.POLYGON_RPC_URL) throw new Error('POLYGON_RPC_URL is not set')
        if (!env.POLYGON_PRIVATE_KEY) throw new Error('POLYGON_PRIVATE_KEY is not set')
        if (!env.POLYGON_ANCHOR_CONTRACT) throw new Error('POLYGON_ANCHOR_CONTRACT is not set')

        _provider = new ethers.JsonRpcProvider(env.POLYGON_RPC_URL)
        _wallet = new ethers.Wallet(env.POLYGON_PRIVATE_KEY, _provider)
        _contract = new ethers.Contract(env.POLYGON_ANCHOR_CONTRACT, ABI, _wallet)
    }
    return { provider: _provider!, wallet: _wallet!, contract: _contract! }
}

// Derive network name from env so testnet credentials don't claim mainnet.
// Set POLYGON_NETWORK=polygon-amoy in Railway for testnet,
// POLYGON_NETWORK=polygon-mainnet for production.
function networkName(): string {
    return env.POLYGON_NETWORK ?? (
        env.POLYGON_RPC_URL?.includes('amoy') ? 'polygon-amoy' : 'polygon-mainnet'
    )
}

// ── GAS CONSTANTS ─────────────────────────────────────────────
const GAS_BUFFER_PCT = 130n   // 30% headroom over estimate
const GAS_CAP = 500_000n  // hard cap — protects wallet if estimateGas misbehaves

// ── WALLET BALANCE ────────────────────────────────────────────
export async function checkAnchorWalletBalance() {
    try {
        const { provider, wallet } = getInstances()
        const balance = await provider.getBalance(wallet.address)
        const balanceMatic = ethers.formatEther(balance)
        return {
            address: wallet.address,
            balanceMatic,
            isSufficient: parseFloat(balanceMatic) >= (env.POLYGON_MIN_BALANCE ?? 0.01),
        }
    } catch (err) {
        resetInstances()
        throw err
    }
}

// ── ANCHOR ────────────────────────────────────────────────────
// BullMQ owns retry logic (3 attempts, exponential backoff in queue.ts).
// This function throws on failure — the worker lets BullMQ handle retries.
// Do NOT add recursive retry here; it compounds with BullMQ retries (3 × 3 = 9 attempts).

export interface AnchorResult {
    txHash: string
    blockNumber: number
    gasUsed: string
    anchoredAt: Date
    network: string
}

export async function anchorHash(credentialId: string, sha256Hash: string): Promise<AnchorResult> {
    // sha256Hash arrives as a hex string without 0x prefix.
    // Solidity expects bytes32 — ethers needs the 0x prefix.
    if (sha256Hash.length !== 64) {
        throw new Error(`Invalid SHA-256 hash length: expected 64 hex chars, got ${sha256Hash.length}`)
    }
    const hashBytes = ('0x' + sha256Hash) as `0x${string}`

    let instances: ReturnType<typeof getInstances>
    try {
        instances = getInstances()
    } catch (err) {
        throw err  // env not configured — don't reset, surface clearly
    }

    const { contract } = instances
    const fn = contract.getFunction('anchor')

    logger.info({ credentialId, sha256Hash, network: networkName() }, 'blockchain: estimating gas')

    let gasLimit: bigint
    try {
        const estimate = await fn.estimateGas(hashBytes)
        gasLimit = BigInt(Math.min(Number((estimate * GAS_BUFFER_PCT) / 100n), Number(GAS_CAP)))
    } catch (err: any) {
        // estimateGas reverts if hash is already anchored — catch and surface clearly
        const msg = err?.message ?? ''
        if (msg.includes('Already anchored')) {
            logger.warn({ credentialId }, 'blockchain: hash already on-chain — marking as anchored')
            return recoverAlreadyAnchored(credentialId, sha256Hash)
        }
        resetInstances()
        throw new Error(`Gas estimation failed: ${msg}`)
    }

    logger.info({ credentialId, gasLimit: gasLimit.toString() }, 'blockchain: submitting tx')

    let tx: ethers.TransactionResponse
    try {
        tx = await fn(hashBytes, { gasLimit })
    } catch (err: any) {
        resetInstances()
        throw new Error(`Tx submission failed: ${err?.message ?? err}`)
    }

    logger.info({ credentialId, txHash: tx.hash }, 'blockchain: tx submitted — awaiting confirmation')

    let receipt: ethers.TransactionReceipt | null
    try {
        receipt = await tx.wait(2)  // wait for 2 confirmations
    } catch (err: any) {
        throw new Error(`Tx confirmation failed (txHash: ${tx.hash}): ${err?.message ?? err}`)
    }

    if (!receipt || receipt.status !== 1) {
        throw new Error(`Tx reverted on-chain: ${tx.hash}`)
    }

    const result: AnchorResult = {
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        anchoredAt: new Date(),
        network: networkName(),
    }

    // Write txHash + blockNumber back to the credential record.

    await db.credential.update({
        where: { id: credentialId },
        data: {
            txHash: result.txHash,
            blockNumber: BigInt(result.blockNumber),
            anchoredAt: result.anchoredAt,
            blockchainNetwork: result.network,
        },
    })

    logger.info({ credentialId, txHash: result.txHash, blockNumber: result.blockNumber, gasUsed: result.gasUsed }, 'blockchain: confirmed')
    return result
}

// ── RECOVER ALREADY-ANCHORED ──────────────────────────────────

async function recoverAlreadyAnchored(credentialId: string, sha256Hash: string): Promise<AnchorResult> {
    const { contract, provider } = getInstances()
    const hashBytes = '0x' + sha256Hash

    const currentBlock = await provider.getBlockNumber()
    const fromBlock = Math.max(0, currentBlock - 100_000)

    const filter = contract.filters.Anchored(hashBytes)
    const events = await contract.queryFilter(filter, fromBlock, currentBlock)

    if (events.length === 0) {
        throw new Error(`Hash reported as already anchored but no event found for ${sha256Hash}`)
    }

    const event = events[0]
    const receipt = await provider.getTransactionReceipt(event.transactionHash)
    if (!receipt) throw new Error(`Could not fetch receipt for recovered tx ${event.transactionHash}`)

    const result: AnchorResult = {
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        anchoredAt: new Date(),
        network: networkName(),
    }

    await db.credential.update({
        where: { id: credentialId },
        data: {
            txHash: result.txHash,
            blockNumber: BigInt(result.blockNumber),
            anchoredAt: result.anchoredAt,
            blockchainNetwork: result.network,
        },
    })

    logger.info({ credentialId, txHash: result.txHash }, 'blockchain: recovered already-anchored credential')
    return result
}

// ── VERIFY ON-CHAIN ───────────────────────────────────────────
// Called by the verification route to confirm a txHash contains
// the expected credential hash. Returns false (not throws) on any failure.
export async function verifyHashOnChain(txHash: string, expectedHash: string): Promise<boolean> {
    try {
        const { provider } = getInstances()
        const receipt = await provider.getTransactionReceipt(txHash)
        if (!receipt) return false

        const iface = new ethers.Interface(ABI)
        for (const log of receipt.logs) {
            try {
                const parsed = iface.parseLog(log)
                if (parsed?.name === 'Anchored') {
                    const onChainHash = (parsed.args[0] as string).toLowerCase()
                    const expected = ('0x' + expectedHash).toLowerCase()
                    return onChainHash === expected
                }
            } catch { /* non-matching log — skip */ }
        }
        return false
    } catch (err) {
        logger.error({ txHash, err }, 'blockchain: on-chain verify failed')
        return false
    }
}

// ── CONTRACT ADDRESS HELPER ───────────────────────────────────
// Used by admin health endpoint to confirm contract is reachable.
export async function pingContract(): Promise<{ ok: boolean; network: string; contract: string }> {
    try {
        const { provider } = getInstances()
        await provider.getBlockNumber()
        return { ok: true, network: networkName(), contract: env.POLYGON_ANCHOR_CONTRACT ?? '(not set)' }
    } catch (err) {
        resetInstances()
        return { ok: false, network: networkName(), contract: env.POLYGON_ANCHOR_CONTRACT ?? '(not set)' }
    }
}