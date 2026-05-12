import { ethers } from 'ethers'
import { env } from '../config/env.js'
import { logger } from './logger.js'
import { db } from './db.js'

const ABI = [
    'function anchor(bytes32 hash) external',
    'function isAnchored(bytes32 hash) external view returns (bool, uint256)',
    'event Anchored(bytes32 indexed hash, uint256 indexed timestamp, address indexed sender)',
]

// ── SINGLETON ─────────────────────────────────────────────────
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

// ── NETWORK NAME ──────────────────────────────────────────────
function networkName(): string {
    return env.POLYGON_NETWORK ?? (env.POLYGON_RPC_URL?.includes('amoy') ? 'polygon-amoy' : 'polygon-mainnet')
}

const GAS_BUFFER_PCT = 130n
const GAS_CAP = 500_000n

// ── EIP-1559 FEE ESTIMATION ───────────────────────────────────
async function estimateFees(provider: ethers.JsonRpcProvider): Promise<{
    maxFeePerGas: bigint
    maxPriorityFeePerGas: bigint
}> {
    const feeData = await provider.getFeeData()
    const base = feeData.gasPrice ?? feeData.maxFeePerGas ?? ethers.parseUnits('50', 'gwei')
    const tip = feeData.maxPriorityFeePerGas ?? ethers.parseUnits('2', 'gwei')
    const max = base * 2n + tip
    return { maxFeePerGas: max, maxPriorityFeePerGas: tip }
}

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
export interface AnchorResult {
    txHash: string
    blockNumber: number
    gasUsed: string
    anchoredAt: Date
    network: string
}

export async function anchorHash(credentialId: string, sha256Hash: string): Promise<AnchorResult> {
    if (sha256Hash.length !== 64) {
        throw new Error(`Invalid SHA-256 hash length: expected 64 hex chars, got ${sha256Hash.length}`)
    }
    const hashBytes = ('0x' + sha256Hash) as `0x${string}`

    const { contract, provider } = getInstances()
    const fn = contract.getFunction('anchor')

    logger.info({ credentialId, sha256Hash, network: networkName() }, 'blockchain: estimating gas')

    // ── EIP-1559 fees ─────────────────────────────────────────
    const { maxFeePerGas, maxPriorityFeePerGas } = await estimateFees(provider)

    let gasLimit: bigint
    try {
        const estimate = await fn.estimateGas(hashBytes)
        gasLimit = BigInt(Math.min(Number((estimate * GAS_BUFFER_PCT) / 100n), Number(GAS_CAP)))
    } catch (err: any) {
        const msg: string = err?.message ?? ''
        if (msg.includes('Already anchored')) {
            logger.warn({ credentialId }, 'blockchain: hash already on-chain — recovering')
            return recoverAlreadyAnchored(credentialId, sha256Hash)
        }
        resetInstances()
        throw new Error(`Gas estimation failed: ${msg}`)
    }

    logger.info({ credentialId, gasLimit: gasLimit.toString(), maxFeePerGas: maxFeePerGas.toString() }, 'blockchain: submitting tx')

    let tx: ethers.TransactionResponse
    try {
        tx = await fn(hashBytes, { gasLimit, maxFeePerGas, maxPriorityFeePerGas })
    } catch (err: any) {
        resetInstances()
        throw new Error(`Tx submission failed: ${err?.message ?? err}`)
    }

    logger.info({ credentialId, txHash: tx.hash }, 'blockchain: awaiting confirmation')

    let receipt: ethers.TransactionReceipt | null
    try {
        receipt = await tx.wait(2)
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

    await db.credential.update({
        where: { id: credentialId },
        data: {
            txHash: result.txHash,
            blockNumber: BigInt(result.blockNumber),
            anchoredAt: result.anchoredAt,
            blockchainNetwork: result.network,
        },
    })

    logger.info({ credentialId, txHash: result.txHash, blockNumber: result.blockNumber }, 'blockchain: confirmed')
    return result
}

// ── RECOVER ALREADY-ANCHORED ──────────────────────────────────
async function recoverAlreadyAnchored(credentialId: string, sha256Hash: string): Promise<AnchorResult> {
    const { contract, provider } = getInstances()
    const hashBytes = '0x' + sha256Hash

    const currentBlock = await provider.getBlockNumber()
    const fromBlock = Math.max(0, currentBlock - 100_000)

    const iface = new ethers.Interface(ABI)
    const filter = iface.encodeFilterTopics('Anchored', [hashBytes])

    const logs = await provider.getLogs({
        address: env.POLYGON_ANCHOR_CONTRACT,
        topics: filter,
        fromBlock,
        toBlock: currentBlock,
    })

    if (!logs.length) {
        throw new Error(`Hash reported as already anchored but no Anchored event found for ${sha256Hash}`)
    }

    const event = logs[0]
    if (!event) throw new Error('Event lookup returned undefined')

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

// ── CONTRACT PING ─────────────────────────────────────────────
export async function pingContract(): Promise<{ ok: boolean; network: string; contract: string }> {
    try {
        const { provider } = getInstances()
        await provider.getBlockNumber()
        return { ok: true, network: networkName(), contract: env.POLYGON_ANCHOR_CONTRACT ?? '(not set)' }
    } catch {
        resetInstances()
        return { ok: false, network: networkName(), contract: env.POLYGON_ANCHOR_CONTRACT ?? '(not set)' }
    }
}