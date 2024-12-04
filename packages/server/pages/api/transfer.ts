import { Connection, Keypair, PublicKey, sendAndConfirmRawTransaction, sendAndConfirmTransaction, Transaction, TransactionSignature } from '@solana/web3.js';
import type { NextApiRequest, NextApiResponse } from 'next';
import base58 from 'bs58';
import { core } from '@candypay/solana-octane-core';
import type { Cache } from 'cache-manager';
import {
    connection,
    ENV_SECRET_KEYPAIR,
    cors,
    rateLimit,
    isReturnedSignatureAllowed,
    ReturnSignatureConfigField,
    cache,
} from '../../src';
import config from '../../../../config.json';

// Endpoint to pay for transactions with an SPL token transfer
export default async function (request: NextApiRequest, response: NextApiResponse) {
    await cors(request, response);
    await rateLimit(request, response);

    // Deserialize a base58 wire-encoded transaction from the request
    const serialized = request.body?.transaction;
    if (typeof serialized !== 'string') {
        response.status(400).send({ status: 'error', message: 'request should contain transaction' });
        return;
    }

    let transaction: Transaction;
    try {
        transaction = Transaction.from(base58.decode(serialized));
    } catch (e) {
        response.status(400).send({ status: 'error', message: "can't decode transaction" });
        return;
    }

    try {

        console.log("Sign with Token Fee")

        const { signature } = await signWithTokenFee(
            connection,
            transaction,
            ENV_SECRET_KEYPAIR,
            config.maxSignatures,
            config.lamportsPerSignature,
            config.endpoints.transfer.tokens.map((token) => core.TokenFee.fromSerializable(token)),
            cache
        );

        console.log(signature);

        // @ts-ignore
        if (config.returnSignature !== undefined) {
            //@ts-ignore
            if (!(await isReturnedSignatureAllowed(request, config.returnSignature as ReturnSignatureConfigField))) {
                response.status(400).send({ status: 'error', message: 'anti-spam check failed' });
                return;
            }
            response.status(200).send({ status: 'ok', signature });
            return;
        }

        transaction.addSignature(ENV_SECRET_KEYPAIR.publicKey, Buffer.from(base58.decode(signature)));

        await sendAndConfirmTransaction(connection, transaction, [ENV_SECRET_KEYPAIR]);

        // Respond with the confirmed transaction signature
        response.status(200).send({ status: 'ok', signature });
    } catch (error) {
        let message = '';
        if (error instanceof Error) {
            message = error.message;
        }
        response.status(400).send({ status: 'error', message });
    }
}

export async function signWithTokenFee(
    connection: Connection,
    transaction: Transaction,
    feePayer: Keypair,
    maxSignatures: number,
    lamportsPerSignature: number,
    allowedTokens: core.TokenFee[],
    cache: Cache,
    sameSourceTimeout = 5000
): Promise<{ signature: string }> {

    console.log("Sign Txn");

    // Prevent simple duplicate transactions using a hash of the message
    let key = `transaction/${base58.encode(core.sha256(transaction.serializeMessage()))}`;
    if (await cache.get(key)) throw new Error('duplicate transaction');
    await cache.set(key, true);

    // Check that the transaction is basically valid, sign it, and serialize it, verifying the signatures
    const { signature, rawTransaction } = await validateTransaction(
        connection,
        transaction,
        feePayer,
        maxSignatures,
        lamportsPerSignature
    );

    console.log("After validate txn");

    await core.validateInstructions(transaction, feePayer);

    console.log("After validate instructions");

    // Check that the transaction contains a valid transfer to Octane's token account
    const transfer = await core.validateTransfer(connection, transaction, allowedTokens);

    console.log("After validate transfer");

    /*
       An attacker could make multiple signing requests before the transaction is confirmed. If the source token account
       has the minimum fee balance, validation and simulation of all these requests may succeed. All but the first
       confirmed transaction will fail because the account will be empty afterward. To prevent this race condition,
       simulation abuse, or similar attacks, we implement a simple lockout for the source token account
       for a few seconds after the transaction.
     */
    key = `transfer/lastSignature/${transfer.keys.source.pubkey.toBase58()}`;
    const lastSignature: number | undefined = await cache.get(key);
    if (lastSignature && Date.now() - lastSignature < sameSourceTimeout) {
        throw new Error('duplicate transfer');
    }
    await cache.set(key, Date.now());

    await core.simulateRawTransaction(connection, rawTransaction);

    console.log("After simulate instructions");

    return { signature: signature };
    
}

export async function validateTransaction(
    connection: Connection,
    transaction: Transaction,
    feePayer: Keypair,
    maxSignatures: number,
    lamportsPerSignature: number
): Promise<{ signature: TransactionSignature; rawTransaction: Buffer }> {
    // Check the fee payer and blockhash for basic validity
    if (!transaction.feePayer?.equals(feePayer.publicKey)) throw new Error('invalid fee payer');
    if (!transaction.recentBlockhash) throw new Error('missing recent blockhash');

    // TODO: handle nonce accounts?

    // Check Octane's RPC node for the blockhash to make sure it's synced and the fee is reasonable
    const message = transaction.compileMessage();
    let feeCalculator = await connection.getFeeForMessage(message);
    
    if (!feeCalculator.value) {
        // Fetch the recent blockhash and fee calculator again
        const { blockhash } = await connection.getLatestBlockhash();
        transaction.recentBlockhash = blockhash;
        feeCalculator = await connection.getFeeForMessage(message);
        if (!feeCalculator.value) throw new Error('blockhash not found after retry');
        if (feeCalculator.value > lamportsPerSignature) throw new Error('fee too high');
    }
    
    if (!feeCalculator.value) throw new Error('blockhash not found');
    if (feeCalculator.value > lamportsPerSignature) throw new Error('fee too high');

    // Check the signatures for length, the primary signature, and secondary signature(s)
    if (!transaction.signatures.length) throw new Error('no signatures');
    if (transaction.signatures.length > maxSignatures) throw new Error('too many signatures');

    const [primary, ...secondary] = transaction.signatures;
    if (!primary.publicKey.equals(feePayer.publicKey)) throw new Error('invalid fee payer pubkey');
    if (primary.signature) throw new Error('invalid fee payer signature');

    for (const signature of secondary) {
        if (!signature.publicKey) throw new Error('missing public key');
        if (!signature.signature) throw new Error('missing signature');
    }

    // Add the fee payer signature
    transaction.partialSign(feePayer);

    // Serialize the transaction, verifying the signatures
    const rawTransaction = transaction.serialize();

    // Return the primary signature (aka txid) and serialized transaction
    return { signature: base58.encode(transaction.signature!), rawTransaction };
}