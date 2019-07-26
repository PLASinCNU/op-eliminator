
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <queue>
/* ================================================================== */
// Global variables 
/* ================================================================== */

using namespace std;
int insCount = 0;
std::ostream * out = &cerr;
//std::ostream * rtnOut = 
ADDRINT main_txt_saddr;
ADDRINT main_img;
bool start = false;
INT32 Usage(){
    
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

VOID dumpInstruction(ADDRINT address, UINT32 insSize, const string* dis){
//    ADDRINT saddr= address -main_img;
    *out<<dec<<insCount<<";";
    *out<<hex<<address<<";";
    for (UINT32 i=0;i<insSize;i++)
	{
		*out<<"\\x"<< setfill('0') << setw(2) << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF);
    }
    *out<<dec<<";"<<*dis;
    *out<<endl;
    insCount++;
}


VOID ImageLoad(IMG img, VOID *v)
{
    if(IMG_IsMainExecutable(img))
       start = true;
//    if(!start)
//        return ;
    
    main_img = IMG_LowAddress(img);

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if(SEC_Name(sec)==".text"){
            main_txt_saddr= SEC_Address(sec);        
        }
        
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Open the RTN.
            RTN_Open( rtn );

//          rtn_addr = rtn_addr-main_img;
//            *out<<rtn_name<<":"<<StringFromAddrint(rtn_addr)<<endl;
            for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {
                string dis=INS_Disassemble(ins);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dumpInstruction),IARG_INST_PTR, IARG_UINT32, INS_Size(ins), IARG_PTR, new string(dis), IARG_END);
            }
            // Close the RTN.
            RTN_Close( rtn );
        }
    }
}


VOID Fini(INT32 code, VOID *v)
{

}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = "calltrace.log";

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    PIN_InitSymbols();
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
