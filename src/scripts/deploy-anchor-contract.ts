import 'dotenv/config'
import { ethers } from 'ethers'

const ABI = [
    'function anchor(bytes32 hash) external',
    'function isAnchored(bytes32 hash) external view returns (bool, uint256)',
    'event Anchored(bytes32 indexed hash, uint256 indexed timestamp, address indexed sender)',
]

const BYTECODE = '0x608060405234801561000f575f80fd5b506101a48061001d5f395ff3fe608060405234801561000f575f80fd5b5060043610610034575f3560e01c80634f0b580114610038578063eecdf92714610075575b5f80fd5b61005a610046366004610157565b5f9081526020819052604090205480151591565b60408051921515835260208301919091520160405180910390f35b610088610083366004610157565b61008a565b005b806100c95760405162461bcd60e51b815260206004820152600a60248201526908adae0e8f240d0c2e6d60b31b60448201526064015b60405180910390fd5b5f81815260208190526040902054156101175760405162461bcd60e51b815260206004820152601060248201526f105b1c9958591e48185b98da1bdc995960821b60448201526064016100c0565b5f8181526020819052604080822042908190559051339284917f84dbb9ce184d1878830cd808f179fc6831bdd837296520e4726615daf660c9cf9190a450565b5f60208284031215610167575f80fd5b503591905056fea2646970667358221220a6cbc1cab3a76d3715cbddaffdd784e9890ca6c5c23ab301f4e602c374e8119d64736f6c63430008180033'

async function getFees(provider: ethers.JsonRpcProvider): Promise<{
    maxFeePerGas: bigint
    maxPriorityFeePerGas: bigint
}> {
    const gasPriceHex = await provider.send('eth_gasPrice', [])
    const gasPrice = BigInt(gasPriceHex)
    const maxPriorityFeePerGas = ethers.parseUnits('30', 'gwei')
    const maxFeePerGas = gasPrice * 2n + maxPriorityFeePerGas
    return { maxFeePerGas, maxPriorityFeePerGas }
}

async function main() {
    const rpcUrl = process.env['POLYGON_RPC_URL']
    const privateKey = process.env['POLYGON_PRIVATE_KEY']
    const confirmed = process.env['CONFIRM_MAINNET_DEPLOY']

    if (confirmed !== 'yes') {
        console.error('CONFIRM_MAINNET_DEPLOY=yes is required to run this script.')
        console.error('This deploys a permanent, non-upgradable contract to Polygon Mainnet.')
        console.error('Run: CONFIRM_MAINNET_DEPLOY=yes npm run deploy:anchor')
        process.exit(1)
    }

    if (!rpcUrl) { console.error('POLYGON_RPC_URL is not set'); process.exit(1) }
    if (!privateKey) { console.error('POLYGON_PRIVATE_KEY is not set'); process.exit(1) }

    const provider = new ethers.JsonRpcProvider(rpcUrl)
    const wallet = new ethers.Wallet(privateKey, provider)

    const network = await provider.getNetwork()
    console.log(`Network: ${network.name} (chainId: ${network.chainId})`)

    if (network.chainId !== 137n) {
        console.error(`This script must run against Polygon Mainnet (chainId 137).`)
        console.error(`Your RPC is pointing at chainId ${network.chainId}.`)
        console.error(`Update POLYGON_RPC_URL in your .env to a Polygon mainnet endpoint.`)
        process.exit(1)
    }

    const balance = await provider.getBalance(wallet.address)
    const balanceMatic = ethers.formatEther(balance)
    console.log(`Wallet:  ${wallet.address}`)
    console.log(`Balance: ${balanceMatic} MATIC`)

    if (parseFloat(balanceMatic) < 0.1) {
        console.error(`Wallet balance too low. Fund with at least 0.1 MATIC before deploying.`)
        console.error(`Send MATIC to: ${wallet.address}`)
        process.exit(1)
    }

    console.log('\nDeploying VeriSureAnchor...')

    const factory = new ethers.ContractFactory(ABI, BYTECODE, wallet)

    const { maxFeePerGas, maxPriorityFeePerGas } = await getFees(provider)
    console.log(`Gas fees: maxFeePerGas=${ethers.formatUnits(maxFeePerGas, 'gwei')} gwei, maxPriorityFeePerGas=${ethers.formatUnits(maxPriorityFeePerGas, 'gwei')} gwei`)

    const contract = await factory.deploy({ maxFeePerGas, maxPriorityFeePerGas })
    const deployTx = contract.deploymentTransaction()

    console.log(`Tx hash: ${deployTx?.hash}`)
    console.log(`Track:   https://polygonscan.com/tx/${deployTx?.hash}`)
    console.log('Waiting for confirmation...')

    await contract.waitForDeployment()

    const address = await contract.getAddress()

    console.log(`\nVeriSureAnchor deployed to Polygon Mainnet`)
    console.log(`\n   Contract address : ${address}`)
    console.log(`   Polygonscan      : https://polygonscan.com/address/${address}`)
    console.log(`\nCopy these into Railway shared variables:`)
    console.log(`\n   POLYGON_ANCHOR_CONTRACT = ${address}`)
    console.log(`   POLYGON_NETWORK         = polygon-mainnet`)

    console.log('\nSanity check...')
    const [anchored] = await (contract as any).isAnchored(
        '0x0000000000000000000000000000000000000000000000000000000000000001'
    ) as [boolean, bigint]
    console.log(`isAnchored test: ${anchored} (expected: false) ${anchored === false ? 'PASS' : 'FAIL'}`)
    console.log('\nNext: verify the contract on Polygonscan (compiler 0.8.24, optimization enabled, 200 runs - try this first).')
    console.log('Then run: npm run backfill:anchors -- --dry-run')
}

main().catch(err => {
    console.error('Deployment failed:', err.message ?? err)
    process.exit(1)
})