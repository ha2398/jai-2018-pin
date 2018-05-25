#include "pin.H"          // para usar APIs do Pin
#include <stdio.h>        // para usar I/O
#include <stdlib.h>       // para usar exit()
#include <string.h>       // para converter números para string
#include <sstream>        // para converter números para string
#include <fstream>        // para imprimir no arquivo de saída
#include <sys/time.h>     // para registro do tempo de processador usado pelo algoritmo
#include <sys/resource.h> // para registro do tempo de processador usado pelo algoritmo

static const UINT32 tam_janela = 32;              // constante que indica o tamanho da janela em bits
static const UINT32 COMPLEMENTO_LINHA_CACHE = 60; // tamanho da linha da cache (64 bytes) - tamanho da janela
static const UINT32 limiar_padrao = 10;           // valor de limiar padrao pré-estabelecido para a janela de 32
static const UINT32 MASCARA_UM = 1;               // máscara usada para setar o bit menos significativo da janela
static std::ofstream arquivo_saida;               // arquivo onde a saída é escrita
static UINT32 limiar;                             // valor de limiar checado durante a execução
static TLS_KEY chave_tls;                         // chave para acesso ao armazenamento local (TLS) das threads

struct JanelaThread{
   UINT32 janela_bits;                  // buffer que guarda os bits (janela)
   UINT8 lixo[COMPLEMENTO_LINHA_CACHE]; // área inútil usada para ocupar uma linha inteira da cache
};

void Uso(){	
   fprintf(stderr, "\nUso: pin -t <Pintool> [-l <Limiar>] [-o <NomeArquivoSaida>] [-logfile <NomeLogDepuracao>] -- <Programa alvo>\n\n"
                   "Opções:\n"
                   "  -l       <Limiar>\t"
                   "  -o       <NomeArquivoSaida>\t"
                   "Indica o nome do arquivo de saida (padrão: $PASTA_CORRENTE/pintool.out)\n"
                   "  -logfile <NomeLogDepuracao>\t"
                   "Indica o nome do arquivo de log de depuracao (padrão: $PASTA_CORRENTE/pintool.log)\n\n");
}

static string converte_double_string(double valor){
   ostringstream oss;
   oss << valor;
   return(oss.str());
}

static string converte_ulong_string(unsigned long int valor){
   ostringstream oss;
   oss << valor;
   return(oss.str());
}

void IniciaThread(THREADID thread_id, CONTEXT *contexto_registradores, int flags_SO, void *v){
   // Aloca espaço para a janela e guarda endereço em apontador 
   JanelaThread* janela_ptr = new JanelaThread;

   // Inicializa a janela
   janela_ptr->janela_bits = 0x00000000;

   // Armazena a janela na área de armazenamento (TLS) da thread
   PIN_SetThreadData(chave_tls, janela_ptr, thread_id);
}

void Fim(INT32 codigo, void *v){
   // salva instante atual para registrar o momento de término
   time_t data_hora = time(0);

   // calcula consumo total de tempo de CPU pelo processo (usuário + sistema)
   struct rusage ru;        
   getrusage(RUSAGE_SELF, &ru);        
   double tempo_fim = static_cast<double>(ru.ru_utime.tv_sec) + static_cast<double>(ru.ru_utime.tv_usec * 0.000001) +
                      static_cast<double>(ru.ru_stime.tv_sec) + static_cast<double>(ru.ru_stime.tv_usec * 0.000001);

   // imprime no arquivo de saída os resultados
   arquivo_saida << " #### Fim: " << string(ctime(&data_hora));
   arquivo_saida << " #### Instrumentação finalizada em " << converte_double_string(tempo_fim) << " segundos" << endl << endl;
}

void PIN_FAST_ANALYSIS_CALL DeslocaJanela(THREADID thread_id, UINT32 num_bits_shift, BOOL desvio_indireto){
   // variável auxiliar: nº de bits setados na janela
   UINT32 num_bits_setados;

   // obtém ponteiro para a janela da thread
   JanelaThread *janela_ptr = static_cast<JanelaThread *>(PIN_GetThreadData(chave_tls, thread_id));

   // se o nº de bits a deslocar é menor que 32 e maior que 0
   if(num_bits_shift < tam_janela){
      // executa shift de num_bits_shift
      janela_ptr->janela_bits <<= num_bits_shift;
   }
   else{ // se o nº de bits a deslocar é maior ou igual ao tamanho da janela
      // zera o buffer
      janela_ptr->janela_bits = 0x00000000;
   }

   // seta o bit menos signif. da janela se a última instrução do BBL for um desvio indireto
   if(desvio_indireto){
      janela_ptr->janela_bits |= MASCARA_UM;
   }

   // usa a instrução de HW POPCNT para contar o número de bits setados na janela
   num_bits_setados = __builtin_popcount(janela_ptr->janela_bits);

   // se o número de bits setados for maior do que o limiar
   if(num_bits_setados > limiar){
      // Ativa uma trava interna do Pin para evitar que threads concorrentes escrevam simultaneamente no arquivo de saída
      PIN_LockClient();

      // imprime mensagem no arquivo de saída
      arquivo_saida << " ####  Suspeita de ataque ROP! O limiar de " << converte_ulong_string(static_cast<unsigned long int>(limiar)) << 
                       " foi superado pelo seguinte valor: " << converte_ulong_string(static_cast<unsigned long int>(num_bits_setados)) << endl;

      // Libera trava
      PIN_UnlockClient();
   }
}

void InstrumentaCodigo(TRACE trace, void *v){
   // percorre todos os BBLs
   for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
      // se a última instrução do BBL for um desvio indireto
      if( INS_IsIndirectBranchOrCall(BBL_InsTail(bbl)) ){
         BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)DeslocaJanela, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, BBL_NumIns(bbl), IARG_BOOL, TRUE, IARG_END);
      }
      else{// se a última instrução do BBL NÃO for um desvio indireto
         BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)DeslocaJanela,  IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, BBL_NumIns(bbl), IARG_BOOL, FALSE, IARG_END);
      }
   }
}

int main(int argc, char *argv[]){
   // Usado para receber da linha de comandos (opção -o) o nome do arquivo de saída. Se não for especificado, usa-se o nome "Pintool.out"
   KNOB<string> KnobArquivoSaida(KNOB_MODE_WRITEONCE, "pintool", "o", "pintool.out", "Nome do arquivo de saida");

   // Usado para receber da linha de comandos (opção -l) o valor de limiar a ser usado. Se não for especificado, usa-se o limiar padrão
   KNOB<UINT32> KnobEntradaLimiar(KNOB_MODE_WRITEONCE, "pintool", "l", converte_ulong_string(static_cast<unsigned long int>(limiar_padrao)), "Valor de limiar a ser usado pela protecao");

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
   
   // Obtém valor do limiar. Se não for passado na linha de comandos, usa limiar padrão
   limiar = KnobEntradaLimiar.Value();
   arquivo_saida << " #### Valor do limiar: " << converte_ulong_string(static_cast<unsigned long int>(limiar)) << endl;

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