/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>
using std::cerr;
using std::endl;
using std::string;
using std::map;
using std::unordered_map;
using std::set;

#define ZSIM_MAGIC_OP_CACHE_RESET (2091)

/* ================================================================== */
// Global variables
/* ================================================================== */

bool inFastForward = true;
// std::ostream* outImem = &cerr;
// std::ostream* outDmem = &cerr;


std::string filename = "";

struct ThreadData {
    UINT64 dTimestamp = 0;
    unordered_map<ADDRINT, UINT64> dAddrTimestampMap;
    map<UINT64, UINT64> dReuseDistances;

    std::unordered_map<ADDRINT, UINT64> iAddrTimestampMap;
    std::unordered_map<UINT64, UINT64> iReuseDistances;
    UINT64 iTimestamp = 0;
};

TLS_KEY tlsKey;
// PIN_LOCK lock;


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
                       "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl
         << "instructions, basic blocks and threads in the application." << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

void dmemAccess(THREADID tid, ADDRINT virtualAddr) {
	if (inFastForward) return;
	ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tlsKey, tid));
        auto& dAddrTimestampMap = tdata->dAddrTimestampMap;
        auto& dReuseDistances = tdata->dReuseDistances;
        auto& dTimestamp = tdata->dTimestamp;
	if (dAddrTimestampMap.find(virtualAddr) != dAddrTimestampMap.end()) {
		UINT64 reuseDistance = dTimestamp - dAddrTimestampMap[virtualAddr];
		if (dReuseDistances.find(reuseDistance) != dReuseDistances.end()) {
			dReuseDistances[reuseDistance] += 1;
		} else {
			dReuseDistances[reuseDistance] = 1;
		}
	}
	dAddrTimestampMap[virtualAddr] = dTimestamp;
	dTimestamp++;
	// PIN_ReleaseLock(&lock);
}

void imemAccess(THREADID tid, ADDRINT virtualAddr) {
	if (inFastForward) return;
	// PIN_GetLock(&lock, tid);
	ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tlsKey, tid));
        auto& iAddrTimestampMap = tdata->iAddrTimestampMap;
        auto& iReuseDistances = tdata->iReuseDistances;
        auto& iTimestamp = tdata->iTimestamp;
	if (iAddrTimestampMap.find(virtualAddr) != iAddrTimestampMap.end()) {
		UINT64 reuseDistance = iTimestamp - iAddrTimestampMap[virtualAddr];
		if (iReuseDistances.find(reuseDistance) != iReuseDistances.end()) {
			iReuseDistances[reuseDistance] += 1;
		} else {
			iReuseDistances[reuseDistance] = 1;
		}
	}
	iAddrTimestampMap[virtualAddr] = iTimestamp;
	iTimestamp++;
	// PIN_ReleaseLock(&lock);
}

VOID HandleMagicOp(THREADID tid, ADDRINT op) {
	if (op != ZSIM_MAGIC_OP_CACHE_RESET) {
		return;
	}
	std::cerr << "reinstrumenting\n";
	inFastForward = false;
	PIN_RemoveInstrumentation();
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleMagicOp, IARG_THREAD_ID, IARG_REG_VALUE, REG_ECX, IARG_END);
    }
    if(INS_IsMemoryRead(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dmemAccess, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_END);
    if(INS_IsMemoryWrite(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dmemAccess, IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)imemAccess, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
}

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* tdata = new ThreadData();
    PIN_SetThreadData(tlsKey, tdata, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tlsKey, tid));

    std::ostringstream thread_ifilename;
    thread_ifilename << filename << "imem_reuse_" << tid << ".out";
    std::ofstream outIFile(thread_ifilename.str());
    for (const auto& [dist, count] : tdata->iReuseDistances) {
        outIFile << dist << " " << count << "\n";
    }
    outIFile.close();

    std::ostringstream thread_dfilename;
    thread_dfilename << filename << "dmem_reuse_" << tid << ".out";
    std::ofstream outDFile(thread_dfilename.str());
    for (const auto& [dist, count] : tdata->iReuseDistances) {
        outDFile << dist << " " << count << "\n";
    }
    outDFile.close();

    delete tdata;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
// VOID Fini(INT32 code, VOID* v)
// {
//     for (const auto& pair : dReuseDistances) {
//         *outDmem << pair.first << ": " << pair.second << std::endl;
//     }
//     for (const auto& pair : iReuseDistances) {
//         *outImem << pair.first << ": " << pair.second << std::endl;
//     }
// }

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty())
    {
	    filename = fileName;
    }

    tlsKey = PIN_CreateThreadDataKey(0);  // 0 = no destructor function
    // PIN_InitLock(&lock);
    
    // Register thread start and end callbacks
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);


    if (KnobCount)
    {
        // Register function to be called to instrument traces
        INS_AddInstrumentFunction(Instruction, 0);

        // Register function to be called when the application exits
        // PIN_AddFiniFunction(Fini, 0);
    }

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
