/*
Implementação da proteção contra ROP denominada "ROPdefender",
que utiliza a estratégia de pilha sombra. Versão para Linux.

Criado por Mateus Felipe Tymburibá Ferreira
Última atualização: 10/02/2014
*/

// importação de bibliotecas do Pin e de C++
#include "pin.H"          // para usar APIs do Pin
#include <stack>          // para usar estrutura de dados Pilha
#include <stdio.h>        // para usar "fprintf" e "snprintf"
#include <stdlib.h>       // para usar "calloc"
#include <string.h>       // para usar "memset" e converter números para string
#include <sstream>        // para converter números para string
#include <fstream>        // para imprimir no arquivo de saída
#include <sys/time.h>     // para registro do tempo de processador usado pelo algoritmo
#include <sys/resource.h> // para registro do tempo de processador usado pelo algoritmo


/**** Variáveis Globais ****/
static TLS_KEY chave_tls;           // chave para acesso ao armazenamento local (TLS) das threads
static std::ofstream arquivo_saida; // arquivo onde a saída é escrita
/**** Fim das Variáveis Globais ****/


// Imprime mensagem indicando opções de uso no prompt de comandos
void Uso(){	
   fprintf(stderr, "\nUso: pin -t <Pintool> [-o <NomeArquivoSaida>] [-logfile <NomeLogDepuracao>] -- <Programa alvo>\n\n"
                   "Opções:\n"
                   "  -o       <NomeArquivoSaida>\t"
                   "Indica o nome do arquivo de saida (padrão: $PASTA_CORRENTE/pintool.out)\n"
                   "  -logfile <NomeLogDepuracao>\t"
                   "Indica o nome do arquivo de log de depuracao (padrão: $PASTA_CORRENTE/pintool.log)\n\n");
}

// Função usada para converter um valor do tipo "double" para o tipo "string"
static string converte_double_string(double valor){
   ostringstream oss;
   oss << valor;
   return(oss.str());
}

// Função chamada ao iniciar uma nova thread
// Instancia objeto para a pilha sombra da nova thread no TLS
void IniciaThread(THREADID tid, CONTEXT * contexto, int flags, void * v){ 
   stack<ADDRINT> *pilhaSombra = new stack<ADDRINT>();
   PIN_SetThreadData(chave_tls, pilhaSombra, tid);
}

// Função chamada quando a aplicação termina de executar.
// Imprime os resultados no arquivo de saída.
void Fim(INT32 codigo, void *v){

   // salva instante atual para registrar o momento de término
   time_t data_hora = time(0);

   // calcula consumo total de tempo de CPU pelo processo (usuário + sistema)
   struct rusage ru;        
   getrusage(RUSAGE_SELF, &ru);        
   double tempo_fim = static_cast<double>(ru.ru_utime.tv_sec) + static_cast<double>(ru.ru_utime.tv_usec * 0.000001) +
                      static_cast<double>(ru.ru_stime.tv_sec) + static_cast<double>(ru.ru_stime.tv_usec * 0.000001);

   // imprime no arquivo de saída os resultados
   arquivo_saida << " #### Instrumentação finalizada em " << converte_double_string(tempo_fim) << " segundos" << endl;
   arquivo_saida << " #### Fim: " << string(ctime(&data_hora)) << endl;
}

// Função registrada junto ao Pin para executar sempre que uma instrução CALL for executada
// Grava o endereço de retorno na pilha sombra da thread correspondente
void PIN_FAST_ANALYSIS_CALL AnaliseCALL(THREADID tid, ADDRINT endereco){	
   // obtém ponteiro para a pilha sombra
   stack<ADDRINT> *pilhaSombra = static_cast<stack<ADDRINT> *>(PIN_GetThreadData(chave_tls, tid));
   // empilha o endereço de retorno na pilha sombra da thread
   pilhaSombra->push(endereco);
}

// Função registrada junto ao Pin para executar sempre que uma instrução RET for executada
// Checa se o endereço de retorno corresponde ao endereço anotado no topo da pilha sombra
void PIN_FAST_ANALYSIS_CALL AnaliseRET(THREADID tid, CONTEXT *contexto){
   // inicializa endereço de retorno anotado na pilha original da thread
   ADDRINT end_ret_original = 0; 

   // inicializa endereço de retorno anotado na pilha sombra
   ADDRINT end_ret_sombra = 0;

   // recupera endereço do topo da pilha original
   ADDRINT * ptr_topo_pilha = (ADDRINT *) PIN_GetContextReg(contexto, REG_STACK_PTR);

   // copia conteúdo do topo da pilha (endereço de retorno) para a variável inicializada
   PIN_SafeCopy(&end_ret_original, ptr_topo_pilha, sizeof(ADDRINT));

   // obtém ponteiro para a pilha sombra
   stack<ADDRINT> *pilhaSombra = static_cast<stack<ADDRINT> *>(PIN_GetThreadData(chave_tls, tid));

   // checa se há algum endereço anotado na pilha sombra
   if(pilhaSombra->size() != 0){
      // obtém endereço de retorno anotado no topo da pilha sombra
      end_ret_sombra = pilhaSombra->top();
      // se os endereços de retorno não coincidirem, sinaliza a suspeita de ataque ROP
      if(end_ret_sombra != end_ret_original){

         // Ativa uma trava interna do Pin para evitar que threads concorrentes escrevam simultaneamente no LOG
         PIN_LockClient();

         arquivo_saida << " #### Suspeita de ataque ROP! O endereço de retorno " << hexstr(end_ret_original, sizeof(ADDRINT)) << " não coincide com o endereço anotado na pilha sombra (" << hexstr(end_ret_sombra, sizeof(ADDRINT)) << ")" << endl;

         // Libera trava
         PIN_UnlockClient();
      }
      // desempilha o endereço anotado no topo da pilha sombra
      pilhaSombra->pop();
   }
   else{
      /* se uma instrução RET está sendo executada e não há endereço de retorno na pilha sombra,
         significa que a paridade CALL-RET foi violada */

      // Ativa uma trava interna do Pin para evitar que threads concorrentes escrevam simultaneamente no LOG
      PIN_LockClient();

      arquivo_saida << " #### Suspeita de ataque ROP! Não há nenhum endereço de retorno anotado na pilha sombra e o programa pretende retornar para o endereço de retorno " << hexstr(end_ret_original, sizeof(ADDRINT)) << endl;

      // Libera trava
      PIN_UnlockClient();
   }
}

// Função registrada junto ao Pin para executar a instrumentação do código.
// Registra junto ao Pin a função "AnaliseCALL" para ser disparada sempre
// que uma instrução de CALL for executada. Da mesma forma,
// registra junto ao Pin a função "AnaliseRET" para ser disparada sempre
// que uma instrução de RET for executada.
// Usa o conceito de BBLs (Basic Blocks) para evitar a instrumentação de
// todas as instruções do código. Ao invés disso, checa apenas a última
// instrução de cada BBL, já que cada BBL possui um único ponto de saída.
void InstrumentaCodigo(TRACE trace, void *v){

   // percorre todos os BBLs
   for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){

      // obtém a última instrução do BBL
      INS ins = BBL_InsTail(bbl);

      // se a última instrução do BBL for uma instrução CALL
      if( INS_IsCall(ins) ){
         // Registra a função "AnaliseCALL" para ser chamada quando o BBL executar,
         // passando o ID da thread e o endereço de retorno a ser empilhado.
         // A opção IPOINT_ANYWHERE permite que o Pin agende a chamada da função de análise
         // em qualquer lugar do BBL para obter uma melhor performance. Também por questões
         // de desempenho (passagem de argumentos otimizada), a opção
         // "IARG_FAST_ANALYSIS_CALL" é utilizada.
         BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)AnaliseCALL, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins) + INS_Size(ins), IARG_END);
      }
      else{
         // se a última instrução do BBL for uma instrução RET
         if(INS_IsRet(ins)){
            // registra a função "AnaliseRET" para ser chamada imediatamente antes de uma instrução RET executar,
            // passando o ID da thread e o ponteiro para o contexto de execução (Pilha, regs, etc).
            // A opção IPOINT_ANYWHERE não pode ser usada porque o topo da pilha (ESP) pode estar diferente
            // daquele válido no momento em que a instrução RET for executar. Por questões
            // de desempenho (passagem de argumentos otimizada), a opção
            // "IARG_FAST_ANALYSIS_CALL" é utilizada.
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AnaliseRET, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_CONTEXT, IARG_END);
         }
      }
   }
}

// Função onde a execução inicia
int main(int argc, char *argv[]){

   // Usado para receber da linha de comandos (opção -o) o nome do arquivo de saída. Se não for especificado, usa-se o nome "Pintool.out"
   KNOB<string> KnobArquivoSaida(KNOB_MODE_WRITEONCE, "pintool", "o", "pintool.out", "Nome do arquivo de saida");

   // Inicializa o Pin e checa os parâmetros
   if(PIN_Init(argc, argv)){
      // imprime mensagem indicando o formato correto dos parâmetros e encerra
      Uso();
      return(1);
   }

   // Abre o arquivo de saída no modo apêndice. Se não for passado um nome para o arquivo na linha de comandos, usa "Pintool.out"
   arquivo_saida.open(KnobArquivoSaida.Value().c_str(), std::ofstream::out | std::ofstream::app);

   // obtem e imprime no arquivo de saída o momento em que a execução está iniciando
   time_t data_hora = time(0);
   arquivo_saida << endl << " #### Inicio: " << string(ctime(&data_hora));

   // obtém a chave para acesso à área de armazenamento local das threads (TLS)
   chave_tls = PIN_CreateThreadDataKey(0);

   // registra a função "Fim" para ser executada quando a aplicação for terminar
   PIN_AddFiniFunction(Fim, NULL);

   // registra a função "IniciaThread" para ser executada quando uma nova thread for iniciar
   PIN_AddThreadStartFunction(IniciaThread, NULL);

   // registra a função "InstrumentaCodigo" para instrumentar os "traces"
   TRACE_AddInstrumentFunction(InstrumentaCodigo, NULL);

   // inicia a execução do programa a ser instrumentado e só retorna quando ele terminar
   PIN_StartProgram();

   // encerra a execução do Pin
   return(0);
}
