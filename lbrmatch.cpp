/**
 * Autor: Hugo Sousa (hugosousa@dcc.ufmg.br)
 *
 * lbrmatch.cpp: Pintool usada para simular a estrutura de
 * um LBR para instruções de chamada de função (CALL) e
 * checar por correspondências entre elas e instruções de
 * retorno.
 */

#include "pin.H"

#include <iostream>
#include <fstream>

using namespace std;

KNOB<string> outFileKnob(KNOB_MODE_WRITEONCE, "pintool",
	"o", "lbr_out.log", "Nome do arquivo de saída.");

KNOB<unsigned int> lbrSizeKnob(KNOB_MODE_WRITEONCE,
	"pintool", "s", "16", "Número de entradas do LBR.");

/**
 * Estrutura de dados LBR (Last Branch Record).
 */

/**
 * Uma entrada do LBR nessa Pintool será composta pelo endereço
 * da instrução CALL e um booleano que indica se esse é um CALL
 * direto (true) ou indireto (false).
 */
typedef pair<ADDRINT, bool> LBREntry;

class LBR {
private:
	LBREntry *buffer;
	unsigned int head, tail, size;
public:
	LBR(unsigned int size) {
		this->size = size;
		head = tail = 0;
		buffer = (LBREntry*) malloc(sizeof(LBREntry) * (size + 1));
	}
	
	bool empty() {
		return (head == tail);
	}
	
	void put(LBREntry item) {
		buffer[head] = item;
		head = (unsigned int) (head + 1) % size;
		
		if (head == tail)
			tail = (unsigned int) (tail + 1) % size;
	}
	
	void pop() {
		if (empty())
			return; 
		
		head = (unsigned int) (head - 1) % size;
	}
	
	LBREntry getLastEntry() {
		if (empty())
			return make_pair(0, false);
		
		unsigned int index = (unsigned int) (head - 1) % size;
		
		return buffer[index];
	}
};

/**
 * Global Variables.
 */

const string done("\t- Done.");
static ofstream outputFile; // Output file

LBR callLBR(lbrSizeKnob.Value()); // CALL LBR
unsigned long callLBRMatches = 0;

VOID doRET(ADDRINT returnAddr) {
	/**
	 * Função de análise para instruções de retorno.
	 *
	 * @returnAddr: Endereço de retorno.
	 */
	 
	LBREntry lastEntry;
	
	/**
	 * Instrução CALL anterior ao endereço de retorno
   * pode estar de 2 a 7 bytes antes dele.
	 *
	 * callLBR é um objeto da classe LBR.
	 */
	lastEntry = callLBR.getLastEntry();
	for (int i = 2; i <= 7; i++) {
		ADDRINT candidate = returnAddr - i;
		
		if (candidate == lastEntry.first) {
			calllLBRMatches++;
			break;
		}
	}
	
	callLBR.pop();
}

VOID doCALL(ADDRINT addr) {
	/**
	 * Função de análise para instruções de chamada de função.
	 *
	 * @addr: O endereço da instrução.
	 */
	
	callLBR.put(make_pair(addr, true));
}

VOID InstrumentCode(TRACE trace, VOID *v) {
  /**
   * Função de instrumentação da Pintool.
   * 
   * Cada bloco básico tem um único ponto de entrada
   * e um único ponto de saída. Assim, CALLs e RETs 
   * somente podem ser encontradas ao fim de blocos
   * básicos.
   */

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
  
    INS tail = BBL_InsTail(bbl);

    if (INS_IsRet(tail)) {
      INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR) doRET,
      	IARG_BRANCH_TARGET_ADDR, IARG_END);
    } else if (INS_IsCall(tail)) {
      INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR) doCALL,
      	IARG_INST_PTR, IARG_END);
    }
  }
}

VOID Fini(INT32 code, VOID *v) {
	/**
	 * Perform necessary operations when the instrumented application is about
	 * to end execution.
	 */
	
	cerr << done << endl;
	outputFile << callLBRMatches << endl;
    outputFile.close();
}

int main(int argc, char *argv[])
{
    // Start Pin and checks parameters.
    if (PIN_Init(argc, argv)) {
        cerr << "[Error] Could not start Pin." << endl;
		return -1;
    }
	
	// Open the output file.
    outputFile.open(outFileKnob.Value().c_str());

    TRACE_AddInstrumentFunction(InstrumentCode, 0);
    PIN_AddFiniFunction(Fini, 0);
	cerr << "[+] Running application." << endl;
    PIN_StartProgram();

    return 0;
}