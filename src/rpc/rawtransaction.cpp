// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "deprecation.h"
#include "key_io.h"
#include "keystore.h"
#include "main.h"
#include "merkleblock.h"
#include "net.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "uint256.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses) {
        a.push_back(EncodeDestination(addr));
    }
    out.push_back(Pair("addresses", a));
}


UniValue TxJoinSplitToJSON(const CTransaction& tx) {
    bool useGroth = tx.fOverwintered && tx.nVersion >= SAPLING_TX_VERSION;
    UniValue vjoinsplit(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vjoinsplit.size(); i++) {
        const JSDescription& jsdescription = tx.vjoinsplit[i];
        UniValue joinsplit(UniValue::VOBJ);

        joinsplit.push_back(Pair("vpub_old", ValueFromAmount(jsdescription.vpub_old)));
        joinsplit.push_back(Pair("vpub_new", ValueFromAmount(jsdescription.vpub_new)));

        joinsplit.push_back(Pair("anchor", jsdescription.anchor.GetHex()));

        {
            UniValue nullifiers(UniValue::VARR);
            BOOST_FOREACH(const uint256 nf, jsdescription.nullifiers) {
                nullifiers.push_back(nf.GetHex());
            }
            joinsplit.push_back(Pair("nullifiers", nullifiers));
        }

        {
            UniValue commitments(UniValue::VARR);
            BOOST_FOREACH(const uint256 commitment, jsdescription.commitments) {
                commitments.push_back(commitment.GetHex());
            }
            joinsplit.push_back(Pair("commitments", commitments));
        }

        joinsplit.push_back(Pair("onetimePubKey", jsdescription.ephemeralKey.GetHex()));
        joinsplit.push_back(Pair("randomSeed", jsdescription.randomSeed.GetHex()));

        {
            UniValue macs(UniValue::VARR);
            BOOST_FOREACH(const uint256 mac, jsdescription.macs) {
                macs.push_back(mac.GetHex());
            }
            joinsplit.push_back(Pair("macs", macs));
        }

        CDataStream ssProof(SER_NETWORK, PROTOCOL_VERSION);
        auto ps = SproutProofSerializer<CDataStream>(ssProof, useGroth);
        boost::apply_visitor(ps, jsdescription.proof);
        joinsplit.push_back(Pair("proof", HexStr(ssProof.begin(), ssProof.end())));

        {
            UniValue ciphertexts(UniValue::VARR);
            for (const ZCNoteEncryption::Ciphertext ct : jsdescription.ciphertexts) {
                ciphertexts.push_back(HexStr(ct.begin(), ct.end()));
            }
            joinsplit.push_back(Pair("ciphertexts", ciphertexts));
        }

        vjoinsplit.push_back(joinsplit);
    }
    return vjoinsplit;
}

UniValue TxShieldedSpendsToJSON(const CTransaction& tx) {
    UniValue vdesc(UniValue::VARR);
    for (const SpendDescription& spendDesc : tx.vShieldedSpend) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("cv", spendDesc.cv.GetHex()));
        obj.push_back(Pair("anchor", spendDesc.anchor.GetHex()));
        obj.push_back(Pair("nullifier", spendDesc.nullifier.GetHex()));
        obj.push_back(Pair("rk", spendDesc.rk.GetHex()));
        obj.push_back(Pair("proof", HexStr(spendDesc.zkproof.begin(), spendDesc.zkproof.end())));
        obj.push_back(Pair("spendAuthSig", HexStr(spendDesc.spendAuthSig.begin(), spendDesc.spendAuthSig.end())));
        vdesc.push_back(obj);
    }
    return vdesc;
}

UniValue TxShieldedOutputsToJSON(const CTransaction& tx) {
    UniValue vdesc(UniValue::VARR);
    for (const OutputDescription& outputDesc : tx.vShieldedOutput) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("cv", outputDesc.cv.GetHex()));
        obj.push_back(Pair("cmu", outputDesc.cm.GetHex()));
        obj.push_back(Pair("ephemeralKey", outputDesc.ephemeralKey.GetHex()));
        obj.push_back(Pair("encCiphertext", HexStr(outputDesc.encCiphertext.begin(), outputDesc.encCiphertext.end())));
        obj.push_back(Pair("outCiphertext", HexStr(outputDesc.outCiphertext.begin(), outputDesc.outCiphertext.end())));
        obj.push_back(Pair("proof", HexStr(outputDesc.zkproof.begin(), outputDesc.zkproof.end())));
        vdesc.push_back(obj);
    }
    return vdesc;
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("overwintered", tx.fOverwintered));
    entry.push_back(Pair("version", tx.nVersion));
    if (tx.fOverwintered) {
        entry.push_back(Pair("versiongroupid", HexInt(tx.nVersionGroupId)));
    }
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    if (tx.fOverwintered) {
        entry.push_back(Pair("expiryheight", (int64_t)tx.nExpiryHeight));
    }
    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("valueZat", txout.nValue));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    UniValue vjoinsplit = TxJoinSplitToJSON(tx);
    entry.push_back(Pair("vjoinsplit", vjoinsplit));

    if (tx.fOverwintered && tx.nVersion >= SAPLING_TX_VERSION) {
        entry.push_back(Pair("valueBalance", ValueFromAmount(tx.valueBalance)));
        UniValue vspenddesc = TxShieldedSpendsToJSON(tx);
        entry.push_back(Pair("vShieldedSpend", vspenddesc));
        UniValue voutputdesc = TxShieldedOutputsToJSON(tx);
        entry.push_back(Pair("vShieldedOutput", voutputdesc));
        if (!(vspenddesc.empty() && voutputdesc.empty())) {
            entry.push_back(Pair("bindingSig", HexStr(tx.bindingSig.begin(), tx.bindingSig.end())));
        }
    }

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

UniValue getrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getrawtransaction \"txid\" ( verbose )\n"
            "\nNOTE: By default this function only works sometimes. This is when the tx is in the mempool\n"
            "or there is an unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option.\n"
            "\nReturn the raw transaction data.\n"
            "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
            "If verbose is non-zero, returns an Object with information about 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

            "\nResult (if verbose is not set or set to 0):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose > 0):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"expiryheight\" : ttt,   (numeric, optional) The block height after which the transaction expires\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"zcashaddress\"          (string) Zcash address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vjoinsplit\" : [        (array of json objects, only for version >= 2)\n"
            "     {\n"
            "       \"vpub_old\" : x.xxx,         (numeric) public input value in " + CURRENCY_UNIT + "\n"
            "       \"vpub_new\" : x.xxx,         (numeric) public output value in " + CURRENCY_UNIT + "\n"
            "       \"anchor\" : \"hex\",         (string) the anchor\n"
            "       \"nullifiers\" : [            (json array of string)\n"
            "         \"hex\"                     (string) input note nullifier\n"
            "         ,...\n"
            "       ],\n"
            "       \"commitments\" : [           (json array of string)\n"
            "         \"hex\"                     (string) output note commitment\n"
            "         ,...\n"
            "       ],\n"
            "       \"onetimePubKey\" : \"hex\",  (string) the onetime public key used to encrypt the ciphertexts\n"
            "       \"randomSeed\" : \"hex\",     (string) the random seed\n"
            "       \"macs\" : [                  (json array of string)\n"
            "         \"hex\"                     (string) input note MAC\n"
            "         ,...\n"
            "       ],\n"
            "       \"proof\" : \"hex\",          (string) the zero-knowledge proof\n"
            "       \"ciphertexts\" : [           (json array of string)\n"
            "         \"hex\"                     (string) output note ciphertext\n"
            "         ,...\n"
            "       ]\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    string strHex = EncodeHexTx(tx);

    if (!fVerbose)
        return strHex;

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

UniValue gettxoutproof(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw runtime_error(
            "gettxoutproof [\"txid\",...] ( blockhash )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
            "\nNOTE: By default this function only works sometimes. This is when there is an\n"
            "unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option or\n"
            "specify the block in which the transaction is included in manually (by blockhash).\n"
            "\nReturn the raw transaction data.\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"block hash\"  (string, optional) If specified, looks for txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n"
        );

    set<uint256> setTxids;
    uint256 oneTxid;
    UniValue txids = params[0].get_array();
    for (size_t idx = 0; idx < txids.size(); idx++) {
        const UniValue& txid = txids[idx];
        if (txid.get_str().length() != 64 || !IsHex(txid.get_str()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ")+txid.get_str());
        uint256 hash(uint256S(txid.get_str()));
        if (setTxids.count(hash))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ")+txid.get_str());
       setTxids.insert(hash);
       oneTxid = hash;
    }

    LOCK(cs_main);

    CBlockIndex* pblockindex = NULL;

    uint256 hashBlock;
    if (params.size() > 1)
    {
        hashBlock = uint256S(params[1].get_str());
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        pblockindex = mapBlockIndex[hashBlock];
    } else {
        CCoins coins;
        if (pcoinsTip->GetCoins(oneTxid, coins) && coins.nHeight > 0 && coins.nHeight <= chainActive.Height())
            pblockindex = chainActive[coins.nHeight];
    }

    if (pblockindex == NULL)
    {
        CTransaction tx;
        if (!GetTransaction(oneTxid, tx, hashBlock, false) || hashBlock.IsNull())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        pblockindex = mapBlockIndex[hashBlock];
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    unsigned int ntxFound = 0;
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
        if (setTxids.count(tx.GetHash()))
            ntxFound++;
    if (ntxFound != setTxids.size())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock mb(block, setTxids);
    ssMB << mb;
    std::string strHex = HexStr(ssMB.begin(), ssMB.end());
    return strHex;
}

UniValue verifytxoutproof(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof generated by gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is invalid\n"
        );

    CDataStream ssMB(ParseHexV(params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    UniValue res(UniValue::VARR);

    vector<uint256> vMatch;
    if (merkleBlock.txn.ExtractMatches(vMatch) != merkleBlock.header.hashMerkleRoot)
        return res;

    LOCK(cs_main);

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

    BOOST_FOREACH(const uint256& hash, vMatch)
        res.push_back(hash.GetHex());
    return res;
}

UniValue createrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...} ( locktime ) ( expiryheight )\n"
            "\nCreate a transaction spending the given inputs and sending to the given addresses.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
            "         \"sequence\":n    (numeric, optional) The sequence number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"addresses\"           (string, required) a json object with addresses as keys and amounts as values\n"
            "    {\n"
            "      \"address\": x.xxx   (numeric, required) The key is the Zcash address, the value is the " + CURRENCY_UNIT + " amount\n"
            "      ,...\n"
            "    }\n"
            "3. locktime              (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
            "4. expiryheight          (numeric, optional, default=" + strprintf("%d", DEFAULT_TX_EXPIRY_DELTA) + ") Expiry height of transaction (if Overwinter is active)\n"
            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n"

            "\nExamples\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ)(UniValue::VNUM)(UniValue::VNUM), true);
    if (params[0].isNull() || params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    UniValue inputs = params[0].get_array();
    UniValue sendTo = params[1].get_obj();

    int nextBlockHeight = chainActive.Height() + 1;
    CMutableTransaction rawTx = CreateNewContextualCMutableTransaction(
        Params().GetConsensus(), nextBlockHeight);

    if (params.size() > 2 && !params[2].isNull()) {
        int64_t nLockTime = params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }
    
    if (params.size() > 3 && !params[3].isNull()) {
        if (NetworkUpgradeActive(nextBlockHeight, Params().GetConsensus(), Consensus::UPGRADE_OVERWINTER)) {
            int64_t nExpiryHeight = params[3].get_int64();
            if (nExpiryHeight < 0 || nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, expiryheight must be nonnegative and less than %d.", TX_EXPIRY_HEIGHT_THRESHOLD));
            }
            rawTx.nExpiryHeight = nExpiryHeight;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expiryheight can only be used if Overwinter is active when the transaction is mined");
        }
    }

    for (size_t idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum())
            nSequence = sequenceObj.get_int();

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    std::set<CTxDestination> destinations;
    vector<string> addrList = sendTo.getKeys();
    for (const std::string& name_ : addrList) {
        CTxDestination destination = DecodeDestination(name_);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Zcash address: ") + name_);
        }

        if (!destinations.insert(destination).second) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
        }

        CScript scriptPubKey = GetScriptForDestination(destination);
        CAmount nAmount = AmountFromValue(sendTo[name_]);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    return EncodeHexTx(rawTx);
}

UniValue decoderawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"hex\"      (string, required) The transaction hex string\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id\n"
            "  \"overwintered\" : bool   (boolean) The Overwintered flag\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"versiongroupid\": \"hex\"   (string, optional) The version group id (Overwintered txs)\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"expiryheight\" : n,     (numeric, optional) Last valid block height for mining transaction (Overwintered txs)\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"t12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) zcash address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vjoinsplit\" : [        (array of json objects, only for version >= 2)\n"
            "     {\n"
            "       \"vpub_old\" : x.xxx,         (numeric) public input value in " + CURRENCY_UNIT + "\n"
            "       \"vpub_new\" : x.xxx,         (numeric) public output value in " + CURRENCY_UNIT + "\n"
            "       \"anchor\" : \"hex\",         (string) the anchor\n"
            "       \"nullifiers\" : [            (json array of string)\n"
            "         \"hex\"                     (string) input note nullifier\n"
            "         ,...\n"
            "       ],\n"
            "       \"commitments\" : [           (json array of string)\n"
            "         \"hex\"                     (string) output note commitment\n"
            "         ,...\n"
            "       ],\n"
            "       \"onetimePubKey\" : \"hex\",  (string) the onetime public key used to encrypt the ciphertexts\n"
            "       \"randomSeed\" : \"hex\",     (string) the random seed\n"
            "       \"macs\" : [                  (json array of string)\n"
            "         \"hex\"                     (string) input note MAC\n"
            "         ,...\n"
            "       ],\n"
            "       \"proof\" : \"hex\",          (string) the zero-knowledge proof\n"
            "       \"ciphertexts\" : [           (json array of string)\n"
            "         \"hex\"                     (string) output note ciphertext\n"
            "         ,...\n"
            "       ]\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    CTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(tx, uint256(), result);

    return result;
}

UniValue decodescript(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decodescript \"hex\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hex\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) Zcash address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) script address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodescript", "\"hexstring\"")
            + HelpExampleRpc("decodescript", "\"hexstring\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.push_back(Pair("p2sh", EncodeDestination(CScriptID(script))));
    return r;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

UniValue signrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
        throw runtime_error(
            "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
            + HelpRequiringPassphrase() + "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
            "     [               (json array of json objects, or 'null' if none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
            "         \"redeemScript\": \"hex\",   (string, required for P2SH) redeem script\n"
            "         \"amount\": value            (numeric, required) The amount spent\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
            "5.  \"branchid\"       (string, optional) The hex representation of the consensus branch id to sign with."
            " This can be used to force signing with consensus rules that are ahead of the node's current height.\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence number\n"
            "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR)(UniValue::VSTR), true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CMutableTransaction> txVariants;
    while (!ssData.empty()) {
        try {
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (const std::exception&) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && !params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = params[2].get_array();
        for (size_t idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            CKey key = DecodeSecret(k.get_str());
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && !params[1].isNull()) {
        UniValue prevTxs = params[1].get_array();
        for (size_t idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR));

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coins->vout[nOut].scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut+1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0;
                if (prevOut.exists("amount")) {
                    coins->vout[nOut].nValue = AmountFromValue(find_value(prevOut, "amount"));
                }
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR)("redeemScript",UniValue::VSTR));
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && !params[3].isNull()) {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);
    // Use the approximate release height if it is greater so offline nodes 
    // have a better estimation of the current height and will be more likely to
    // determine the correct consensus branch ID.  Regtest mode ignores release height.
    int chainHeight = chainActive.Height() + 1;
    if (Params().NetworkIDString() != "regtest") {
        chainHeight = std::max(chainHeight, APPROX_RELEASE_HEIGHT);
    }
    // Grab the current consensus branch ID
    auto consensusBranchId = CurrentEpochBranchId(chainHeight, Params().GetConsensus());

    if (params.size() > 4 && !params[4].isNull()) {
        consensusBranchId = ParseHexToUInt32(params[4].get_str());
        if (!IsConsensusBranchId(consensusBranchId)) {
            throw runtime_error(params[4].get_str() + " is not a valid consensus branch id");
        }
    } 
    
    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;
        const CAmount& amount = coins->vout[txin.prevout.n].nValue;

        SignatureData sigdata;
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mergedTx, i, amount, nHashType), prevPubKey, sigdata, consensusBranchId);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CMutableTransaction& txv, txVariants) {
            sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount), sigdata, DataFromTransaction(txv, i), consensusBranchId);
        }

        UpdateTransaction(mergedTx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount), consensusBranchId, &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
    result.push_back(Pair("complete", fComplete));
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors));
    }

    return result;
}

UniValue sendrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL));

    // parse hex string from parameter
    CTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    CCoinsViewCache &view = *pcoinsTip;
    const CCoins* existingCoins = view.AccessCoins(hashTx);
    bool fHaveMempool = mempool.exists(hashTx);
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000;
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, !fOverrideFees)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    RelayTransaction(tx);

    return hashTx.GetHex();
}


bool find_unspent_notes(std::vector<SendManyInputJSOP> &z_inputs_, uint256 utxo, int jsindex) {

    int mindepth_ = 1;
    std::vector<CSproutNotePlaintextEntry> entries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes_ok(entries, utxo, jsindex, mindepth_);
    }

    for (CSproutNotePlaintextEntry & entry : entries) {
        z_inputs_.push_back(SendManyInputJSOP(entry.jsop, entry.plaintext.note(entry.address), CAmount(entry.plaintext.value())));
    }

    if (z_inputs_.size() == 0) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(z_inputs_.begin(), z_inputs_.end(), [](SendManyInputJSOP i, SendManyInputJSOP j) -> bool {
        return ( std::get<2>(i) > std::get<2>(j));
    });

    return true;
}



class SproutNote_wrapper{
public:
    SproutNote_wrapper(libzcash::SproutNote note_v):
            a_pk(note_v.a_pk),rho(note_v.rho),r(note_v.r),value_(note_v.value()){}
    SproutNote_wrapper(){}
    uint256 a_pk;
    uint256 rho;
    uint256 r;
    uint64_t value_;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(a_pk);
        READWRITE(rho);
        READWRITE(r);
        READWRITE(value_);
    }

};

class CTxIn_z{
public:
    CTxIn_z(JSOutPoint jso_v, SproutNote_wrapper note_v, ZCIncrementalWitness vInputWitness_v, uint256 inputAuchor_v):
            jso(jso_v), note(note_v), vInputWitness(vInputWitness_v), inputAuchor(inputAuchor_v){}

    CTxIn_z(){}
    JSOutPoint jso;
    SproutNote_wrapper note;
    ZCIncrementalWitness vInputWitness;
    uint256 inputAuchor;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*const_cast<JSOutPoint*>(&jso));
        READWRITE(*const_cast<SproutNote_wrapper*>(&note));
        READWRITE(*const_cast<ZCIncrementalWitness*>(&vInputWitness));
        READWRITE(inputAuchor);

    }
};

typedef  std::array<unsigned char, ZC_MEMO_SIZE> memoArray;
class JSOutput_wrapper{
public:

    JSOutput_wrapper( std::string address_, CAmount value_, std::string memo_):
            address(address_), value(value_), memo(memo_){}

    JSOutput_wrapper(){}

    std::string address;
    CAmount value;
    std::string memo;  // 0xF6 is invalid UTF8 as per spec, rest of array is 0x00

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*const_cast<std::string*>(&address));
        READWRITE(*const_cast<CAmount*>(&value));
        READWRITE(*const_cast<std::string*>(&memo));
    }
};

class CTxOut_z{
public:
    CTxOut_z(JSOutput_wrapper jso_v):jso(jso_v){}
    CTxOut_z(){}

    JSOutput_wrapper  jso;
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*const_cast<JSOutput_wrapper*>(&jso));
    }
};

class CTransaction_z{
public:
    CTransaction  tx;

    std::vector<CTxIn_z> vinz;
    std::vector<CTxOut_z> voutz;

    uint32_t consensusBranchId_;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*const_cast<CTransaction *>(&tx));
        READWRITE(*const_cast<std::vector <CTxIn_z> *>(&vinz));
        READWRITE(*const_cast<std::vector <CTxOut_z> *>(&voutz));
        READWRITE(consensusBranchId_);
    }
};

std::string EncodeHexTx_z(const CTransaction_z &rawTx ){
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << rawTx;
    return HexStr(ssTx.begin(), ssTx.end());
}

bool DecodeHexTx_z (CTransaction_z& tx, const std::string& strHexTx){
    if (!IsHex(strHexTx))
        return false;

    std::vector<unsigned char> txData(ParseHex(strHexTx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> tx;
    }
    catch (const std::exception& e) {
        printf("DecodeHexTx_z exception:%s \n", e.what());
        return false;
    }

    return true;
}


int find_output_ok(UniValue obj, int n) {
    UniValue outputMapValue = find_value(obj, "outputmap");
    if (!outputMapValue.isArray()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing outputmap for JoinSplit operation");
    }

    UniValue outputMap = outputMapValue.get_array();
    assert(outputMap.size() == ZC_NUM_JS_OUTPUTS);
    for (size_t i = 0; i < outputMap.size(); i++) {
        if (outputMap[i].get_int() == n) {
            return i;
        }
    }

    throw std::logic_error("n is not present in outputmap");
}


bool Find_Spendingkey_PaymentAddr(const std::vector<SpendingKey> &vecKeys, const uint256 a_pk,
                                  PaymentAddress &paymentaddress, SpendingKey &spendingkey)
{
    for(int i=0; i<vecKeys.size(); i++)
    {
        SpendingKey spendingkeyOne = vecKeys[i];
        assert(boost::get<libzcash::SproutSpendingKey>(&spendingkeyOne) != nullptr);
        auto key = boost::get<libzcash::SproutSpendingKey>(spendingkeyOne);
        auto addr = key.address();

        if(addr.a_pk == a_pk){
            spendingkey = spendingkeyOne;
            paymentaddress = addr;
            return true;
        }
    }

    return false;
}


std::array<unsigned char, ZC_MEMO_SIZE> get_memo_from_hex_string(std::string s)
{
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0x00}};

    std::vector<unsigned char> rawMemo = ParseHex(s.c_str());

    // If ParseHex comes across a non-hex char, it will stop but still return results so far.
    size_t slen = s.length();
    if (slen % 2 != 0 || (slen > 0 && rawMemo.size() != slen / 2)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo must be in hexadecimal format");
    }

    if (rawMemo.size() > ZC_MEMO_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Memo size of %d is too big, maximum allowed is %d", rawMemo.size(), ZC_MEMO_SIZE));
    }

    // copy vector into boost array
    int lenMemo = rawMemo.size();
    for (int i = 0; i < ZC_MEMO_SIZE && i < lenMemo; i++) {
        memo[i] = rawMemo[i];
    }
    return memo;
}
UniValue perform_joinsplit(
        AsyncJoinSplitInfo & info,
        std::vector<boost::optional < ZCIncrementalWitness>> witnesses,
        uint256 anchor,
        const SpendingKey &spendingkey_,
        CTransaction_z &tx_z,
        const unsigned char *pjoinSplitPrivKey_)
{

    printf("perform 1 \n");
    //if (anchor.IsNull()) {
    //    throw std::runtime_error("anchor is null");
    //}
    printf("perform 2 \n");
    if (!(witnesses.size() == info.notes.size())) {
        throw runtime_error("number of notes and witnesses do not match");
    }
    printf("perform 3 \n");
    for (size_t i = 0; i < witnesses.size(); i++) {
        if (!witnesses[i]) {
            throw runtime_error("joinsplit input could not be found in tree");
        }
        printf("perform 4 \n");
        info.vjsin.push_back(JSInput(*witnesses[i], info.notes[i], boost::get<libzcash::SproutSpendingKey>(spendingkey_)));
    }

    printf("perform 5 \n");
    // Make sure there are two inputs and two outputs
    while (info.vjsin.size() < ZC_NUM_JS_INPUTS) {
        info.vjsin.push_back(JSInput());
    }

    printf("perform 6 \n");
    while (info.vjsout.size() < ZC_NUM_JS_OUTPUTS) {
        info.vjsout.push_back(JSOutput());
    }

    if (info.vjsout.size() != ZC_NUM_JS_INPUTS || info.vjsin.size() != ZC_NUM_JS_OUTPUTS) {
        throw runtime_error("unsupported joinsplit input/output counts");
    }

    printf("perform 7 \n");
    CMutableTransaction mtx(tx_z.tx);

    // Generate the proof, this can take over a minute.
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs
            {info.vjsin[0], info.vjsin[1]};
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs
            {info.vjsout[0], info.vjsout[1]};
    std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
    std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;

    uint256 esk; // payment disclosure - secret

    printf("perform 8 \n");
    JSDescription jsdesc = JSDescription::Randomized(
            mtx.fOverwintered && (mtx.nVersion >= SAPLING_TX_VERSION),
            *pzcashParams,
            tx_z.tx.joinSplitPubKey,
            anchor,
            inputs,
            outputs,
            inputMap,
            outputMap,
            info.vpub_old,
            info.vpub_new,
            true,
            &esk); // parameter expects pointer to esk, so pass in address
    {
        printf("perform 9 \n");
        auto verifier = libzcash::ProofVerifier::Strict();
        if (!(jsdesc.Verify(*pzcashParams, verifier, tx_z.tx.joinSplitPubKey))) {
            throw std::runtime_error("error verifying joinsplit");
        }
    }

    printf("perform 10 \n");
    mtx.vjoinsplit.push_back(jsdesc);

    // Empty output script.
    CScript scriptCode;
    CTransaction signTx(mtx);
    printf("perform 11 \n");
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, tx_z.consensusBranchId_);

    printf("perform 12 \n");
    // Add the signature
    if (!(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
                               dataToBeSigned.begin(), 32,
                               pjoinSplitPrivKey_
    ) == 0))
    {
        throw std::runtime_error("crypto_sign_detached failed");
    }

    printf("perform 13 \n");
    // Sanity check
    if (!(crypto_sign_verify_detached(&mtx.joinSplitSig[0],
                                      dataToBeSigned.begin(), 32,
                                      mtx.joinSplitPubKey.begin()
    ) == 0))
    {
        throw std::runtime_error("crypto_sign_verify_detached failed");
    }

    printf("perform 14 \n");
    CTransaction rawTx(mtx);
    tx_z.tx = rawTx;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;

    std::string encryptedNote1;
    std::string encryptedNote2;
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x00);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[0];
        ss2 << jsdesc.h_sig(*pzcashParams, tx_z.tx.joinSplitPubKey);

        encryptedNote1 = HexStr(ss2.begin(), ss2.end());
    }
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x01);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[1];
        ss2 << jsdesc.h_sig(*pzcashParams, tx_z.tx.joinSplitPubKey);

        encryptedNote2 = HexStr(ss2.begin(), ss2.end());
    }

    UniValue arrInputMap(UniValue::VARR);
    UniValue arrOutputMap(UniValue::VARR);
    for (size_t i = 0; i < ZC_NUM_JS_INPUTS; i++) {
        arrInputMap.push_back(static_cast<uint64_t>(inputMap[i]));
    }
    for (size_t i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        arrOutputMap.push_back(static_cast<uint64_t>(outputMap[i]));
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("encryptednote1", encryptedNote1));
    obj.push_back(Pair("encryptednote2", encryptedNote2));
    obj.push_back(Pair("rawtxn", HexStr(ss.begin(), ss.end())));
    obj.push_back(Pair("inputmap", arrInputMap));
    obj.push_back(Pair("outputmap", arrOutputMap));
    return obj;
}

UniValue perform_joinsplit(AsyncJoinSplitInfo & info, std::vector<JSOutPoint> & outPoints,
                           const SpendingKey  &spendingKey_,
                           CTransaction_z &tx_,
                           const unsigned char *pjoinSplitPrivKey_)
{
    printf("perform a4  \n");
    std::vector<boost::optional < ZCIncrementalWitness>> witnesses;
    uint256 anchor;
    {
        pwalletMain->GetNoteWitnesses(outPoints, witnesses, anchor);
    }
    return perform_joinsplit(info, witnesses, anchor, spendingKey_, tx_, pjoinSplitPrivKey_);
}

UniValue perform_joinsplit(AsyncJoinSplitInfo & info,  const SpendingKey &spendingKey_,
                           CTransaction_z &tx_, const unsigned char *pjoinSplitPrivKey_)
{
    printf("perform a5  \n");
    std::vector<boost::optional < ZCIncrementalWitness>> witnesses;
    printf("perform a5 1  \n");
    uint256 anchor;
    {
        printf("perform a5 2  \n");
        anchor = uint256();
        //anchor = pcoinsTip->GetBestAnchor(SPROUT);    // As there are no inputs, ask the wallet for the best anchor
        printf("perform a5 3 \n");
    }
    return perform_joinsplit(info, witnesses, anchor, spendingKey_, tx_, pjoinSplitPrivKey_);
}

//add by okcoin
UniValue z_createrawtransaction_ok(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 3)
        throw runtime_error(
                "z_createrawtransaction_ok [{\"txid\":\"id\",\"z_addr\":},...] {\"address\":amount,...} ( locktime )\n"
                "\nCreate a transaction spending the given inputs and sending to the given addresses.\n"
                "Returns hex-encoded raw transaction.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n"

                "\nArguments:\n"
                "1. \"transactions\"        (string, required) A json array of json objects\n"
                "     [\n"
                "       {\n"
                "         \"txid\":\"id\",  (string, required) The transaction id\n"
                "         \"vout\":n        (numeric, required) The output number\n"
                "         \"sequence\":n    (numeric, optional) The sequence number\n"
                "       }\n"
                "       ,...\n"
                "     ]\n"
                "2. \"transactions\"        (string, required) A json array of json objects\n"
                "     [\n"
                "       {\n"
                "         \"txid\":\"id\",  (string, required) The transaction id\n"
                "         \"jsindex\":n        \n"
                "       }\n"
                "       ,...\n"
                "     ]\n"
                "3. \"amounts\"             (array, required) An array of json objects representing the amounts to send.\n"
                "    [{\n"
                "      \"address\":\"address\"  (string, required) The address is a taddr or zaddr\n"
                "      \"amount\":amount    (numeric, required) The numeric amount in  is the value\n"
                "      \"memo\":\"memo\"        (string, optional) If the address is a zaddr, raw data represented in hexadecimal string format\n"
                "    }, ... ]\n"

                "\nResult:\n"
                "\"transaction\"            (string) hex string of the transaction\n"

                "\nExamples\n"
        );

    printf("z_c 1 \n");
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VARR)(UniValue::VARR), true);
    if (params[0].isNull() || params[1].isNull() || params[2].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 and  3 must be non-null");
    printf("z_c 2 \n");
    UniValue inputs_t = params[0].get_array();
    UniValue inputs_z = params[1].get_array();
    UniValue outputs = params[2].get_array();

    if (outputs.size()==0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, amounts array is empty.");
    if( inputs_t.size()>0 && inputs_z.size()>0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, only one input  is allowed");

    int nextBlockHeight = 306750;//chainActive.Height() + 1;
    CMutableTransaction rawTx = CreateNewContextualCMutableTransaction(
            Params().GetConsensus(), nextBlockHeight);
    printf("z_c 3 nextBlockHeight:%d\n", nextBlockHeight);
    CTransaction_z  rawTx_z;

    // Grab the current consensus branch ID
    {
        LOCK(cs_main);
        rawTx_z.consensusBranchId_ = CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());
    }

    if (NetworkUpgradeActive(nextBlockHeight, Params().GetConsensus(), Consensus::UPGRADE_OVERWINTER)) {
        if (rawTx.nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD){
            throw JSONRPCError(RPC_INVALID_PARAMETER, "nExpiryHeight must be less than TX_EXPIRY_HEIGHT_THRESHOLD.");
        }
    }

    printf("z_c 4 \n");
    if (params.size() > 3 && !params[3].isNull()) {
        int64_t nLockTime = params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    for (size_t idx = 0; idx < inputs_t.size(); idx++) {
        const UniValue& input = inputs_t[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum())
            nSequence = sequenceObj.get_int();

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);
        rawTx.vin.push_back(in);
    }

    printf("z_c 6 \n");
    for (size_t idx = 0; idx < inputs_z.size(); idx++) {
        const UniValue& input = inputs_z[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");
        const UniValue& vout_v = find_value(o, "jsindex");
        int jsindex = vout_v.get_int();

        std::vector<SendManyInputJSOP> z_inputs;
        std::deque<SendManyInputJSOP> zInputsDeque;
        printf("z_c 51 \n");
        if( find_unspent_notes(z_inputs, txid, jsindex))
        {
            // Copy zinputs and zoutputs to more flexible containers
            for (auto o : z_inputs) {
                zInputsDeque.push_back(o);
            }
        }
        printf("z_c 51 \n");
        //
        // consume input source
        //
        while (zInputsDeque.size() > 0) {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            SendManyInputJSOP t = zInputsDeque.front();
            JSOutPoint jso = std::get<0>(t);
            SproutNote note = std::get<1>(t);
            CAmount noteFunds = std::get<2>(t);
            zInputsDeque.pop_front();

            std::vector<JSOutPoint> vOutPoints = { jso };
            uint256 inputAuchor;

            std::vector<boost::optional<ZCIncrementalWitness>> vInputWitnesses;
            pwalletMain->GetNoteWitnesses(vOutPoints, vInputWitnesses, inputAuchor);

            ZCIncrementalWitness ss;
            rawTx_z.vinz.push_back(CTxIn_z(jso, SproutNote_wrapper(note), vInputWitnesses[0].get(), inputAuchor));
        }
    }

    printf("z_c 7 \n");
    // Keep track of addresses to spot duplicates
    set<std::string> setAddress;
    for (const UniValue& o : outputs.getValues()) {
        if (!o.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        printf("z_c 71 \n");
        // sanity check, report error if unknown key-value pairs
        for (const string& name_ : o.getKeys()) {
            std::string s = name_;
            if (s != "address" && s != "amount" && s!="memo")
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, unknown key: ")+s);
        }
        printf("z_c 72 \n");
        string address = find_value(o, "address").get_str();
        printf("z_c 73 \n");
        bool isZaddr = false;
        CTxDestination taddr = DecodeDestination(address);
        printf("z_c 74 address :%s\n", address.c_str());
        if (!IsValidDestination(taddr)) {
            printf("z_c 75 \n");
            if (IsValidPaymentAddressString(address)) {
                printf("z_c 76 \n");
                isZaddr = true;
            } else {
                printf("z_c 76 1\n");
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, unknown address format: ")+address );
            }
        }
        printf("z_c 77 \n");
        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+address);
        printf("z_c 7 8\n");
        setAddress.insert(address);
        printf("z_c 7 9\n");
        UniValue memoValue = find_value(o, "memo");
        printf("z_c 7 0\n");
        string memo;
        if (!memoValue.isNull()) {
            printf("z_c 711\n");
            memo = memoValue.get_str();
            printf("z_c 7 12\n");
            if (!isZaddr) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo cannot be used with a taddr.  It can only be used with a zaddr.");
            } else if (!IsHex(memo)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected memo data in hexadecimal format.");
            }
            if (memo.length() > ZC_MEMO_SIZE*2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,  strprintf("Invalid parameter, size of memo is larger than maximum allowed %d", ZC_MEMO_SIZE ));
            }
        }
        printf("z_c 713 \n");
        UniValue av = find_value(o, "amount");
        printf("z_c 7 14\n");
        CAmount nAmount = AmountFromValue( av );
        printf("z_c 7 15 \n");
        if (nAmount < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, amount must be positive");
        printf("z_c 7 16\n");
        if (isZaddr) {
            printf("z_c 7 17\n");
            rawTx_z.voutz.push_back(CTxOut_z(JSOutput_wrapper(address, nAmount, memo)));
        } else {
            printf("z_c 7 18\n");
            CScript scriptPubKey = GetScriptForDestination(taddr);
            CTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);
        }
    }

    rawTx_z.tx = CTransaction(rawTx);
    printf("z_c 8 \n");
    return EncodeHexTx_z(rawTx_z);
}

UniValue z_signrawtransaction_ok(const UniValue& params, bool fHelp){

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
                "z_signrawtransaction_ok hexstring: z_createrawtransaction_ok\n"
                "Sign inputs for raw transaction_z (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n"
                "The third optional argument (may be null) is an array of base58-encoded private\n"
                "keys that, if given, will be the only keys used to sign the transaction.\n"
                #ifdef ENABLE_WALLET
                + HelpRequiringPassphrase() + "\n"
                #endif

                "\nArguments:\n"
                "1. \"hexstring\"     (string, required) The transaction hex string\n"
                "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
                "     [               (json array of json objects, or 'null' if none provided)\n"
                "       {\n"
                "         \"txid\":\"id\",             (string, required) The transaction id\n"
                "         \"vout\":n,                  (numeric, required) The output number\n"
                "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
                "         \"redeemScript\": \"hex\",   (string, required for P2SH) redeem script\n"
                "         \"amount\": value            (numeric, required) The amount spent\n"
                "       }\n"
                "       ,...\n"
                "    ]\n"
                "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
                "    [                  (json array of strings, or 'null' if none provided)\n"
                "      \"privatekey\"   (string) private key in base58-encoding\n"
                "      ,...\n"
                "    ]\n"
                "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
                "       \"ALL\"\n"
                "       \"NONE\"\n"
                "       \"SINGLE\"\n"
                "       \"ALL|ANYONECANPAY\"\n"
                "       \"NONE|ANYONECANPAY\"\n"
                "       \"SINGLE|ANYONECANPAY\"\n"

                "\nResult:\n"
                "{\n"
                "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
                "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
                "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
                "    {\n"
                "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
                "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
                "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
                "      \"sequence\" : n,            (numeric) Script sequence number\n"
                "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
                "    }\n"
                "    ,...\n"
                "  ]\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("signrawtransaction", "\"myhex\"")
                + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );
    printf("z_sign 1\n");
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR), true);
    printf("z_sign 2\n");
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    printf("z_sign 3\n");
    CTransaction_z tx_z;
    std::string strHex = params[0].get_str();
    if (!DecodeHexTx_z(tx_z, strHex))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX_z decode failed");

    printf("z_sign 4\n");
    CTransaction tx_ = tx_z.tx;
    printf("z_sign5 \n");
    CAmount t_outputs_total = 0;
    for (int i=0; i<tx_z.tx.vout.size(); i++) {
        t_outputs_total += tx_z.tx.vout[i].nValue;
    }
    printf("z_sign 6\n");
    /**
    * SCENARIO #1
    *
    * taddr -> taddrs
    *
    * There are no zaddrs or joinsplits involved.
    */
    printf("z_sign 7\n");
    if (tx_z.vinz.size() == 0 && tx_z.voutz.size() == 0){
        UniValue rawtxnValue = EncodeHexTx(tx_z.tx);
        if (rawtxnValue.isNull()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for raw transaction");
        }
        printf("z_sign 8\n");
        UniValue paramTx(UniValue::VARR);
        paramTx.push_back(rawtxnValue.get_str());
        if(params.size() >= 3){
            paramTx.push_back(params[1].get_array());
            paramTx.push_back(params[2].get_array());
        }
        printf("z_sign 9\n");
        if(params.size() == 4){
            paramTx.push_back(params[3].get_str());
        }
        printf("z_sign 10\n");
        return signrawtransaction(paramTx, false);
    }
    /**
     * SCENARIO #1 end
     */

    printf("z_sign 10\n");
    uint256 joinSplitPubKey_;
    unsigned char joinSplitPrivKey_[crypto_sign_SECRETKEYBYTES];

    CMutableTransaction mtx(tx_);
    crypto_sign_keypair(joinSplitPubKey_.begin(), joinSplitPrivKey_);
    mtx.joinSplitPubKey = joinSplitPubKey_;
    tx_z.tx = CTransaction(mtx);
    printf("z_sign 10\n");
    // The key is the result string from calling JSOutPoint::ToString()
    std::unordered_map<std::string, WitnessAnchorData> jsopWitnessAnchorMap;
    std::deque<SendManyInputJSOP> zInputsDeque;

    for (int i=0; i<tx_z.vinz.size(); i++) {
        JSOutPoint jso = tx_z.vinz[i].jso;
        SproutNote_wrapper noteWrapper = tx_z.vinz[i].note;
        ZCIncrementalWitness wit = tx_z.vinz[i].vInputWitness;
        uint256 inputAnchor = tx_z.vinz[i].inputAuchor;

        SproutNote note(noteWrapper.a_pk, noteWrapper.value_, noteWrapper.rho, noteWrapper.r);
        zInputsDeque.push_back(SendManyInputJSOP(tx_z.vinz[i].jso, note, note.value()));

        jsopWitnessAnchorMap[ jso.ToString() ] = WitnessAnchorData{ wit, inputAnchor };
    }

    std::deque<SendManyRecipient> zOutputsDeque;
    for (int i=0; i<tx_z.voutz.size(); i++) {
        zOutputsDeque.push_back(SendManyRecipient(tx_z.voutz[i].jso.address, tx_z.voutz[i].jso.value, tx_z.voutz[i].jso.memo));
    }
    printf("z_sign 20\n");

    /**
    * SCENARIO #2
    *
    * taddr -> taddrs
     *      -> zaddrs
    *
    */

    if (tx_z.vinz.size() == 0 && tx_z.voutz.size() > 0){
        printf("z_sign 21\n");
        // Create joinsplits, where each output represents a zaddr recipient.
        UniValue obj(UniValue::VOBJ);
        while (zOutputsDeque.size() > 0) {
            AsyncJoinSplitInfo info;
            info.vpub_old = 0;
            info.vpub_new = 0;
            int n = 0;
            while (n++<ZC_NUM_JS_OUTPUTS && zOutputsDeque.size() > 0) {
                SendManyRecipient smr = zOutputsDeque.front();
                std::string address = std::get<0>(smr);
                CAmount value = std::get<1>(smr);
                std::string hexMemo = std::get<2>(smr);
                zOutputsDeque.pop_front();

                PaymentAddress pa = DecodePaymentAddress(address);
                JSOutput jso = JSOutput(boost::get<libzcash::SproutPaymentAddress>(pa), value);
                if (hexMemo.size() > 0) {
                    jso.memo = get_memo_from_hex_string(hexMemo);
                }
                info.vjsout.push_back(jso);

                // Funds are removed from the value pool and enter the private pool
                info.vpub_old += value;
            }

            SpendingKey spendingk;
            printf("z_sign 22\n");
            obj = perform_joinsplit(info, spendingk, tx_z, joinSplitPrivKey_);
            printf("z_sign 23\n");
        }

        UniValue rawtxnValue = find_value(obj, "rawtxn");
        if (rawtxnValue.isNull()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for raw transaction");
        }
        UniValue paramTx(UniValue::VARR);
        paramTx.push_back(rawtxnValue.get_str());
        if(params.size() == 3){
            paramTx.push_back(params[1].get_array());
            paramTx.push_back(params[2].get_array());
        }
        printf("z_sign 24\n");
        if(params.size() == 4){
            paramTx.push_back(params[3].get_str());
        }
        printf("z_sign 25\n");
        return signrawtransaction(paramTx, false);
    }
    /**
     * SCENARIO #2 end
     */


    //zaddr: spendingkey
    std::vector<SpendingKey> vecSecret;
    if (params.size() > 2 && !params[2].isNull()) {
        UniValue keys = params[2].get_array();
        for (size_t idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            std::string strSecret = k.get_str();

            auto spendingkey = DecodeSpendingKey(strSecret);
            if (!IsValidSpendingKey(spendingkey)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid spending key");
            }

            vecSecret.push_back(spendingkey);
        }
    }
    /**
    * SCENARIO #3
    *
    * zaddr -> taddrs
     *      -> zaddrs
    *
    * There are no zaddrs or joinsplits involved.
    */

    UniValue obj(UniValue::VOBJ);
    CAmount jsChange = 0;   // this is updated after each joinsplit
    int changeOutputIndex = -1; // this is updated after each joinsplit if jsChange > 0
    bool vpubNewProcessed = false;  // updated when vpub_new for miner fee and taddr outputs is set in last joinsplit
    CAmount vpubNewTarget = ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE;
    if (t_outputs_total > 0) {
        vpubNewTarget += t_outputs_total;
    }

    // Keep track of treestate within this transaction
    boost::unordered_map<uint256, ZCIncrementalMerkleTree, CCoinsKeyHasher> intermediates;
    std::vector<uint256> previousCommitments;

    PaymentAddress frompaymentaddress_;
    SpendingKey spendingkey_;

    while (!vpubNewProcessed) {
        AsyncJoinSplitInfo info;
        info.vpub_old = 0;
        info.vpub_new = 0;

        CAmount jsInputValue = 0;
        uint256 jsAnchor;
        std::vector<boost::optional<ZCIncrementalWitness>> witnesses;

        JSDescription prevJoinSplit;

        // Keep track of previous JoinSplit and its commitments
        if (tx_.vjoinsplit.size() > 0) {
            prevJoinSplit = tx_.vjoinsplit.back();
        }

        // If there is no change, the chain has terminated so we can reset the tracked treestate.
        if (jsChange==0 && tx_.vjoinsplit.size() > 0) {
            intermediates.clear();
            previousCommitments.clear();
        }

        //
        // Consume change as the first input of the JoinSplit.
        //
        if (jsChange > 0) {
            LOCK2(cs_main, pwalletMain->cs_wallet);

            // Update tree state with previous joinsplit
            ZCIncrementalMerkleTree tree;
            auto it = intermediates.find(prevJoinSplit.anchor);
            if (it != intermediates.end()) {
                tree = it->second;
            } else if (!pcoinsTip->GetSproutAnchorAt(prevJoinSplit.anchor, tree)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not find previous JoinSplit anchor");
            }

            assert(changeOutputIndex != -1);
            boost::optional<ZCIncrementalWitness> changeWitness;
            int n = 0;
            for (const uint256& commitment : prevJoinSplit.commitments) {
                tree.append(commitment);
                previousCommitments.push_back(commitment);
                if (!changeWitness && changeOutputIndex == n++) {
                    changeWitness = tree.witness();
                } else if (changeWitness) {
                    changeWitness.get().append(commitment);
                }
            }
            if (changeWitness) {
                witnesses.push_back(changeWitness);
            }
            jsAnchor = tree.root();
            intermediates.insert(std::make_pair(tree.root(), tree));    // chained js are interstitial (found in between block boundaries)

            // Decrypt the change note's ciphertext to retrieve some data we need
            ZCNoteDecryption decryptor(boost::get<libzcash::SproutSpendingKey>(spendingkey_).receiving_key());
            auto hSig = prevJoinSplit.h_sig(*pzcashParams, tx_.joinSplitPubKey);
            try {
                SproutNotePlaintext plaintext = SproutNotePlaintext::decrypt(
                        decryptor,
                        prevJoinSplit.ciphertexts[changeOutputIndex],
                        prevJoinSplit.ephemeralKey,
                        hSig,
                        (unsigned char) changeOutputIndex);

                SproutNote note = plaintext.note(boost::get<libzcash::SproutPaymentAddress>(frompaymentaddress_));
                info.notes.push_back(note);

                jsInputValue += plaintext.value();

            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Error decrypting output note of previous JoinSplit: %s", e.what()));
            }
        }

        //
        // Consume spendable non-change notes
        //
        std::vector<SproutNote> vInputNotes;
        std::vector<JSOutPoint> vOutPoints;
        std::vector<boost::optional<ZCIncrementalWitness>> vInputWitnesses;
        uint256 inputAnchor;
        int numInputsNeeded = (jsChange>0) ? 1 : 0;
        while (numInputsNeeded++ < ZC_NUM_JS_INPUTS && zInputsDeque.size() > 0) {
            SendManyInputJSOP t = zInputsDeque.front();
            JSOutPoint jso = std::get<0>(t);
            SproutNote note = std::get<1>(t);
            CAmount noteFunds = std::get<2>(t);
            zInputsDeque.pop_front();

            WitnessAnchorData wad = jsopWitnessAnchorMap[ jso.ToString() ];
            vInputWitnesses.push_back(wad.witness);
            if (inputAnchor.IsNull()) {
                inputAnchor = wad.anchor;
            } else if (inputAnchor != wad.anchor) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Selected input notes do not share the same anchor");
            }

            vOutPoints.push_back(jso);
            vInputNotes.push_back(note);

            if(!Find_Spendingkey_PaymentAddr(vecSecret, note.a_pk, frompaymentaddress_, spendingkey_))
                throw JSONRPCError(RPC_WALLET_ERROR, "no secrect input");

            jsInputValue += noteFunds;
        }

        // Add history of previous commitments to witness
        if (vInputNotes.size() > 0) {

            if (vInputWitnesses.size()==0) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not find witness for note commitment");
            }

            for (auto & optionalWitness : vInputWitnesses) {
                if (!optionalWitness) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Witness for note commitment is null");
                }
                ZCIncrementalWitness w = *optionalWitness; // could use .get();
                if (jsChange > 0) {
                    for (const uint256& commitment : previousCommitments) {
                        w.append(commitment);
                    }
                    if (jsAnchor != w.root()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Witness for spendable note does not have same anchor as change input");
                    }
                }
                witnesses.push_back(w);
            }

            // The jsAnchor is null if this JoinSplit is at the start of a new chain
            if (jsAnchor.IsNull()) {
                jsAnchor = inputAnchor;
            }

            // Add spendable notes as inputs
            std::copy(vInputNotes.begin(), vInputNotes.end(), std::back_inserter(info.notes));
        }

        // Find recipient to transfer funds to
        std::string address, hexMemo;
        CAmount value = 0;
        if (zOutputsDeque.size() > 0) {
            SendManyRecipient smr = zOutputsDeque.front();
            address = std::get<0>(smr);
            value = std::get<1>(smr);
            hexMemo = std::get<2>(smr);
            zOutputsDeque.pop_front();
        }

        // Reset change
        jsChange = 0;
        CAmount outAmount = value;

        // Set vpub_new in the last joinsplit (when there are no more notes to spend or zaddr outputs to satisfy)
        if (zOutputsDeque.size() == 0 && zInputsDeque.size() == 0) {
            assert(!vpubNewProcessed);
            if (jsInputValue < vpubNewTarget) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   ("Insufficient funds  sign crawtransaction_ok"));
            }
            outAmount += vpubNewTarget;
            info.vpub_new += vpubNewTarget; // funds flowing back to public pool
            vpubNewProcessed = true;
            jsChange = jsInputValue - outAmount;
            assert(jsChange >= 0);
        }
        else {
            // This is not the last joinsplit, so compute change and any amount still due to the recipient
            if (jsInputValue > outAmount) {
                jsChange = jsInputValue - outAmount;
            } else if (outAmount > jsInputValue) {
                // Any amount due is owed to the recipient.  Let the miners fee get paid first.
                CAmount due = outAmount - jsInputValue;
                SendManyRecipient r = SendManyRecipient(address, due, hexMemo);
                zOutputsDeque.push_front(r);

                // reduce the amount being sent right now to the value of all inputs
                value = jsInputValue;
            }
        }

        // create output for recipient
        if (address.empty()) {
            assert(value==0);
            info.vjsout.push_back(JSOutput());  // dummy output while we accumulate funds into a change note for vpub_new
        } else {
            PaymentAddress pa = DecodePaymentAddress(address);
            JSOutput jso = JSOutput(boost::get<libzcash::SproutPaymentAddress>(pa), value);
            if (hexMemo.size() > 0) {
                jso.memo = get_memo_from_hex_string(hexMemo);
            }
            info.vjsout.push_back(jso);
        }

        // create output for any change
        if (jsChange>0) {
            info.vjsout.push_back(JSOutput(boost::get<libzcash::SproutPaymentAddress>(frompaymentaddress_), jsChange));
        }

        obj = perform_joinsplit(info, witnesses, jsAnchor, spendingkey_, tx_z, joinSplitPrivKey_);

        if (jsChange > 0) {
            changeOutputIndex = find_output_ok(obj, 1);
        }
    }

    UniValue rawtxnValue = find_value(obj, "rawtxn");
    if (rawtxnValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for raw transaction");
    }

    UniValue paramTx(UniValue::VARR);
    paramTx.push_back(rawtxnValue);
    for (int i=1; i<params.size(); i++){
        if (i == 2)
            paramTx.push_back( UniValue(UniValue::VARR));
        else
            paramTx.push_back(params[i]);
    }

    return signrawtransaction(paramTx, false);
}
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "rawtransactions",    "getrawtransaction",      &getrawtransaction,      true  },
    { "rawtransactions",    "createrawtransaction",   &createrawtransaction,   true  },
    { "rawtransactions",    "decoderawtransaction",   &decoderawtransaction,   true  },
    { "rawtransactions",    "decodescript",           &decodescript,           true  },
    { "rawtransactions",    "sendrawtransaction",     &sendrawtransaction,     false },
    { "rawtransactions",    "signrawtransaction",     &signrawtransaction,     false }, /* uses wallet if enabled */

    { "blockchain",         "gettxoutproof",          &gettxoutproof,          true  },
    { "blockchain",         "verifytxoutproof",       &verifytxoutproof,       true  },

    { "rawtransactions",    "z_createrawtransaction_ok",   &z_createrawtransaction_ok,   true  },
    { "rawtransactions",    "z_signrawtransaction_ok",     &z_signrawtransaction_ok,     false },
};

void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
