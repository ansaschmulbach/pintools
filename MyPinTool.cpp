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


/* ================================================================== */
// Global variables
/* ================================================================== */

std::ostream* outImem = &cerr;
std::ostream* outDmem = &cerr;
UINT64 dTimestamp = 0;
unordered_map<ADDRINT, UINT64> dAddrTimestampMap;
map<UINT64, UINT64> dReuseDistances;
UINT64 iTimestamp = 0;
unordered_map<ADDRINT, UINT64> iAddrTimestampMap;
map<UINT64, UINT64> iReuseDistances;


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

void dmemAccess(ADDRINT virtualAddr) {
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
}

void imemAccess(ADDRINT virtualAddr) {
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
}
/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    if(INS_IsMemoryRead(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dmemAccess, IARG_MEMORYREAD_EA, IARG_END);
    if(INS_IsMemoryWrite(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dmemAccess, IARG_MEMORYWRITE_EA, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)imemAccess, IARG_INST_PTR, IARG_END);
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
    for (const auto& pair : dReuseDistances) {
        *outDmem << pair.first << ": " << pair.second << std::endl;
    }
    for (const auto& pair : iReuseDistances) {
        *outImem << pair.first << ": " << pair.second << std::endl;
    }
}

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
        outDmem = new std::ofstream(("dmem_" + fileName).c_str());
        outImem = new std::ofstream(("imem_" + fileName).c_str());
    }

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        INS_AddInstrumentFunction(Instruction, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
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
