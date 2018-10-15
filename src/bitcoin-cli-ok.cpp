// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "rpcserver.h"
#include "init.h"
#include "main.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"
#include "rpcserver.h"
#include "rpcclient.h"
#include "com_okcoin_vault_jni_zcash_CZcashOk.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>

#include <stdexcept>

#include <stdio.h>

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

static bool fDaemon;

void WaitForShutdown(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;

    //
    // Parameters
    //
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version"))
    {
        std::string strUsage = _("Zcash Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n" + PrivacyInfo();

        if (mapArgs.count("-version"))
        {
            strUsage += LicenseInfo();
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                        "  zcashd [options]                     " + _("Start Zcash Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try
    {
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const missing_zcash_conf& e) {
            fprintf(stderr,
                    (_("Before starting zcashd, you need to create a configuration file:\n"
                       "%s\n"
                       "It can be completely empty! That indicates you are happy with the default\n"
                       "configuration of zcashd. But requiring a configuration file to start ensures\n"
                       "that zcashd won't accidentally compromise your privacy if there was a default\n"
                       "option you needed to change.\n"
                       "\n"
                       "You can look at the example configuration file for suggestions of default\n"
                       "options that you may want to change. It should be in one of these locations,\n"
                       "depending on how you installed Zcash:\n") +
                     _("- Source code:  %s\n"
                       "- .deb package: %s\n")).c_str(),
                    GetConfigFile().string().c_str(),
                    "contrib/debian/examples/zcash.conf",
                    "/usr/share/doc/zcash/examples/zcash.conf");
            return false;
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        if (!SelectParamsFromCommandLine()) {
            fprintf(stderr, "Error: Invalid combination of -regtest and -testnet.\n");
            return false;
        }

        // Command-line RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "zcash:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            fprintf(stderr, "Error: There is no RPC client functionality in zcashd. Use the zcash-cli utility instead.\n");
            exit(EXIT_FAILURE);
        }
#ifndef WIN32
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            fprintf(stdout, "Zcash server starting\n");

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);

        }
#endif
        SoftSetBoolArg("-server", false);

        fRet = AppInit2(threadGroup, scheduler);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    /*if (!fRet)
    {
        Interrupt(threadGroup);
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else {
        WaitForShutdown(&threadGroup);
    }
    Shutdown();
     */

    return fRet;
}


//CRPCTable rpcTalbe;
extern const CRPCTable tableRPC;
UniValue CommandLineRPC(std::string strMethod, std::vector<std::string> &args)
{
    std::string strPrint;
    UniValue result;
    int nRet = 0;
    try {
        UniValue params = RPCConvertValues(strMethod, args);

        const UniValue reply = tableRPC.execute(strMethod, params);
        result = reply;
        // Parse reply
      /*  if (reply.isStr())
        {
            printf("CommandLineRPC reply isStr func:%s \n", strMethod.c_str());
            result = reply;
        }
        else{
            printf("CommandLineRPC reply  func:%s \n", strMethod.c_str());
            result = find_value(reply, "result");
        }

        const UniValue& error  = find_value(reply, "error");

        if (!error.isNull()) {
            // Error
            printf("CommandLineRPC enter error \n");
            int code = error["code"].get_int();
            strPrint = "error: " + error.write();
            nRet = abs(code);
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg  = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: "+errCode.getValStr()+"\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n"+errMsg.get_str();
            }
        } else {
            // Result
            printf("CommandLineRPC find result error else\n");
            if (result.isNull()){
                strPrint = "";
            }
            else if (result.isStr()) {
                strPrint = result.get_str();
            }
            else
                strPrint = result.write(2);
        }*/
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    }
    catch (const std::runtime_error &e) {
        strPrint = std::string("error runtime: ") + e.what();
        nRet = EXIT_FAILURE;
    }
    catch (const UniValue & e){

        std::vector<UniValue>  vals = e.getValues();
        //for(int i=0; i<vals.size(); i++){
        if (vals.size()>1)
            PrintExceptionContinue(NULL, vals[1].get_str().c_str());
        //}
        throw;
    }
    catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC() in");
        throw;
    }

    if (strPrint != "") {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }

    return result;
}

bool g_AppInitRPC = false;
UniValue EXEMethod(const std::string strMethod,  std::vector <std::string> &params_formt){

    UniValue result("");
    try {
        if (!g_AppInitRPC)
        {
            //SelectBaseParams(CBaseChainParams::TESTNET);
            /* char params[2][15] = {"java", "ok_getAddress"};
             int ret = AppInitRPC(2, (char**)params);
             if (ret != CONTINUE_EXECUTION)
                 return result;
             */
            SetupEnvironment();

            // Connect bitcoind signal handlers
            //noui_connect();

            int argc = 0;
            char* argv[] = {};

            bool bRet = AppInit(argc, argv);
            if(false == bRet){
                std::exception e;
                PrintExceptionContinue(&e, "ApInit return false");
                return result;
            }
        }
        g_AppInitRPC = true;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return result;
    }
    catch (...) {
        PrintExceptionContinue(NULL, "AppInitRPC()");
        return result;
    }

    try {
        result = CommandLineRPC(strMethod, params_formt);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
    }

    return result;

}




/*
 * Class:     com_okcoin_vault_jni_zcash_CZcashOk
 * Method:    execute
 * Signature: (Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_com_okcoin_vault_jni_zcash_CZcashOk_execute
        (JNIEnv *env, jclass ob, jstring netType, jstring params)
{

    const char*  netTypes = env->GetStringUTFChars(netType, 0);
    const char*  strParams = env->GetStringUTFChars(params, 0);



    std::vector<std::string> vArgs;
    boost::split(vArgs, strParams, boost::is_any_of(" \t"));

    std::string strMethod = vArgs[0];

    for (int i=0; i<vArgs.size(); i++){
        printf("%d:%s \n", i, vArgs[i].c_str());
    }

    std::vector<std::string> paramEn  = std::vector<std::string>(vArgs.begin()+1, vArgs.end());
    UniValue ret = EXEMethod(strMethod, paramEn);

    printf("Java_com_okcoin_vault_jni_zcash_CZcashOk_execute EXEMethod end  \n");

    std::list<std::string> kvList;
    std::string context;
    ret.feedStringList(kvList, context);
    int len = kvList.size();

    jclass cls = env->FindClass("java/lang/Object");
    jobjectArray mjobjectArray = (jobjectArray)env->NewObjectArray(len, cls, NULL);

    int i=0;
    for(std::list<std::string>::iterator it = kvList.begin(); it != kvList.end(); it++, i++){
        jstring mystring=env->NewStringUTF((*it).c_str());
        env->SetObjectArrayElement(mjobjectArray,
                                   i,(jobject)mystring);
    }

    printf("Java_com_okcoin_vault_jni_zcash_CZcashOk_execute  end kvSize:%d \n", kvList.size());
    return mjobjectArray;

}


int main(int argc, char* argv[])
{
    //SetupEnvironment();

    // Connect bitcoind signal handlers
    //noui_connect();

    return 0;// (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}
