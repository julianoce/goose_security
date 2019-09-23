/* Para rodar manualmente no linux, use:
 * sudo gcc gcry.c recebe_goose_decript.c aes.c sha256.c cmac.c -lgcrypt -lgpg-error -o recebe_goose_decript
 * sudo ./recebe_goose_decript 1 0
 * parâmetro 1 significa quantidade de pacotes, deve ser inteiro positivo
 * parâmetro 2 significa modo de seguranca, varia de 0 a 4
 */

#include <stdio.h>          //printf
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>         //strncpy
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>         //ifreq
#include <unistd.h>         //close
#include <netinet/ether.h>
#include <sys/time.h>       //gettimeofday
#include "sha256.h"
#include "aes.h"
#include "cmac.h"
#include "gcry.h"           //para cadastrar rsa
#include "math.h"

#define DESTINO_MAC0    0x3c
#define DESTINO_MAC1    0xa8
#define DESTINO_MAC2    0x2a
#define DESTINO_MAC3    0xe4
#define DESTINO_MAC4    0x00
#define DESTINO_MAC5    0x17

//#define ETHER_TYPE	0x0001 //ETH_P_802_3
#define ETHER_TYPE	0x0003 //ETH_P_ALL
//#define ETHER_TYPE	0x8100 //ETH_P_8021Q
//#define ETHER_TYPE	0x0800 //ETH_P_IP

// #define DEFAULT_IF      "eth0"
#define DEFAULT_IF      "wlp3s0"
#define TAMANHO_BUF     256

#define IPAD 0x36 //definido na RFC2104
#define OPAD 0x5c //definido na RFC2104
#define SHA256_BLOCK 64 //tamanho do bloco interno do algoritmo, 512 bits

void imprimeHex(char *msg, int tamanho);
char *geraHash(char *texto, int tamanho);
char *geraDecifraRSA(char *cifra, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho);

int main(int argc, char *argv[])
{
    int t1, t2;
    struct timeval total1, total2;
    int t_buffer;
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buffer[TAMANHO_BUF];
    clock_t t1_clock, t2_clock;
    int ratio = 6;
    int min_time = 1;
    int max_time = 1000;
    int sq_num = 1;
    int an = min_time * pow(ratio, (sq_num-1));
    int st_num_ini = 0;
    int st_num = 3;
    struct ifreq if_idx;
    struct ifreq if_mac;
    struct sockaddr_ll socket_address;
    int pacotes_enviados = 0;

   /* Get interface name */
    char ifName[IFNAMSIZ];
    strcpy(ifName, DEFAULT_IF);

	strcpy(ifName, DEFAULT_IF);
	uint8_t *chave = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

	printf("\n#  ##### Programa Recebe Pkt Goose #####  #\n");
	int qtd_pacotes = 1;
    int tipo_seguranca = 0;
    int conteudo_extra = 0;
    if(argc > 1) sscanf(argv[1], "%d", &qtd_pacotes);
    if(argc > 2) sscanf(argv[2], "%d", &tipo_seguranca);

    if(tipo_seguranca==0) printf("Tipo de Segurança: NENHUMA\n");
    if(tipo_seguranca==1) printf("Tipo de Segurança: HASH SHA256\n");
    if(tipo_seguranca==2) printf("Tipo de Segurança: CRIPTOGRAFIA SIMÉTRICA AES128\n");
    if(tipo_seguranca==3) printf("Tipo de Segurança: CRIPTOGRAFIA ASSIMÉTRICA RSA2048\n");
    if(tipo_seguranca==4) printf("Tipo de Segurança: HMAC (Hash-based Message Authentication Code)\n");
    if(tipo_seguranca==5) printf("Tipo de Segurança: CMAC (Cypher-based Message Authentication Code)\n");
    if(tipo_seguranca<0 || tipo_seguranca>5) return 0;

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buffer;
	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be rchar *geraHash(char *texto, int tamanho);
char *geraDecifraAES(char *texto, char *chave, int tamanho);
char *geraDecifraRSA(char *cifra, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho);
char *geraHMAC(char *msg, int tamanho, char *chave, int tamanho_chave);eused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
   
    t1 = clock();

    
    printf("Recebedor de pacotes ativo, recebendo pacotes.\n");
    int tam_seguranca = 0;
    if(tipo_seguranca>0 && tipo_seguranca<5) tam_seguranca = 32;
    else if(tipo_seguranca==5) tam_seguranca = 16;
    int count = 0, x=0, y=0;

    while(count < qtd_pacotes){

        numbytes = recvfrom(sockfd, buffer, TAMANHO_BUF, 0, NULL, NULL);
        x++;
        if (buffer[12] == 0x88 && buffer[13] == 0xb8) {
            // printf("Mensagem Goose Recebida!\n");
            y++;
                /* Abrir RAW socket para enviar */

            gcrypt_init();
            gcry_error_t err;
            gcry_sexp_t pubk, privk;
            FILE* lockf = fopen("rsa-key.sp", "rb");
            if (!lockf) xerr("fopen() falhou");
            /* Grab a key pair password and create an AES context with it. */
            gcry_cipher_hd_t aes_hd;
            get_aes_ctx(&aes_hd);
            /* Read and decrypt the key pair from disk. */
            size_t rsa_len = get_keypair_size(2048);
            char* rsa_buf = calloc(1, rsa_len);
            if (!rsa_buf) xerr("malloc: buffer RSA nao pode ser alocado.");

            if (fread(rsa_buf, rsa_len, 1, lockf) != 1) xerr("fread() falhou");

            err = gcry_cipher_decrypt(aes_hd, (unsigned char*) rsa_buf, rsa_len, NULL, 0);
            if (err) xerr("gcrypt: falha na decriptografia do par de chaves.");
            /* Load the key pair components into sexps. */
            gcry_sexp_t rsa_keypair;
            err = gcry_sexp_new(&rsa_keypair, rsa_buf, rsa_len, 0);
            pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
            privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
            //printf("%d\n",gcry_sexp_length(rsa_keypair));

            gcry_sexp_release(rsa_keypair);
            gcry_cipher_close(aes_hd);
            free(rsa_buf);
            fclose(lockf);

            uint8_t payload[numbytes-tam_seguranca];
            for(int i=0; i<numbytes-tam_seguranca; i++) payload[i] = buffer[i];
            uint8_t rabicho[tam_seguranca];
            for(int i=0; i<tam_seguranca; i++) rabicho[i] = buffer[(numbytes-tam_seguranca)+i];

            if(strncmp(geraDecifraRSA(geraHash(payload, sizeof(payload)), pubk, privk, 32), rabicho, 32) != 0){
                        //printf("Cifra RSA incorreta.\n");
                        //return 0;
            }

            if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
                perror("socket");
                exit(1);
            }
            /* Captura o indice da interface para enviar */
            memset(&if_idx, 0, sizeof(struct ifreq));
            strncpy(if_idx.ifr_name, "wlp3s0", IFNAMSIZ-1);
            if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
                perror("SIOCGIFINDEX");

            /* Captura o endereço MAC da interface para enviar */
            memset(&if_mac, 0, sizeof(struct ifreq));
            strncpy(if_mac.ifr_name, "wlp3s0", IFNAMSIZ-1);
            if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
                perror("SIOCGIFHWADDR");

            /* Index of the network device */
            socket_address.sll_ifindex = if_idx.ifr_ifindex;
            /* Address length */
            socket_address.sll_halen = ETH_ALEN;
            //fim do codigo de envio************************


            int aux_sqnum = 0;
            if(st_num_ini == st_num){
                while (an < (max_time/ratio))
                {
                    sq_num = sq_num + 1;
                    an = min_time * (pow(ratio, sq_num-1));
                    printf("%d\n", an);
                    sleep(an/1000);
                    aux_sqnum = aux_sqnum + 1;
                t_buffer = 109;
                    if(sendto(sockfd, payload, t_buffer, 0,
                    (struct sockaddr*)&socket_address,
                        sizeof(struct sockaddr_ll)) < 0)
                            printf("Falha no envio\n");
                    

                    pacotes_enviados = pacotes_enviados + 1;
                }
                if(an >= max_time/ratio){
                    an = max_time;
                    printf("%d\n", an);
                    sleep(an/1000);
                    aux_sqnum = aux_sqnum + 1;
                    t_buffer = 109;
                    if(sendto(sockfd, payload, t_buffer, 0,
                    (struct sockaddr*)&socket_address,
                        sizeof(struct sockaddr_ll)) < 0)
                            printf("Falha no envio\n");
                    pacotes_enviados = pacotes_enviados + 1;
                    
                }
            }

            if(st_num_ini < st_num){
                printf("%d\n", st_num_ini);
                while(an < max_time/ratio){
                    sq_num = sq_num + 1;
                    an = min_time * (pow(ratio, sq_num-1));
                    printf("%d\n", an);
                    sleep(an/1000);
                    aux_sqnum = aux_sqnum + 1;
                    t_buffer = 109;
                    if(sendto(sockfd, payload, t_buffer, 0,
                    (struct sockaddr*)&socket_address,
                        sizeof(struct sockaddr_ll)) < 0)
                            printf("Falha no envio\n");
                    pacotes_enviados = pacotes_enviados + 1;
                    t2 = clock();
                    gettimeofday(&total2, NULL);
                }

                if(an >= max_time/ratio){
                    sq_num = sq_num + 1;
                    an = max_time;
                    printf("%d\n", an);
                    sleep(an/1000);
                    aux_sqnum = aux_sqnum + 1;
                    t_buffer = 109;

                    if(sendto(sockfd, payload, t_buffer, 0,
                    (struct sockaddr*)&socket_address,
                        sizeof(struct sockaddr_ll)) < 0)
                            printf("Falha no envio\n");
                    pacotes_enviados = pacotes_enviados + 1;                
                    sq_num = 2;
                    an = min_time * (pow(ratio, sq_num-1));
                    float diff = ((float)(t2 - t1) / 1000000.0F ) * 1000;   
                    printf("%f\n",diff); 
                    printf("%s\n", "Comeca a retransmissao....");
                }
                gcry_sexp_release(pubk);
                gcry_sexp_release(privk);
                st_num_ini = st_num_ini + 1;
                aux_sqnum = 0;
            }
            else{
                sleep(max_time/1000);
                aux_sqnum = aux_sqnum + 1;
                t_buffer = 109;                
                if(sendto(sockfd, payload, t_buffer, 0,
                    (struct sockaddr*)&socket_address,
                        sizeof(struct sockaddr_ll)) < 0)
                            printf("Falha no envio\n");
                pacotes_enviados = pacotes_enviados + 1;
            }
            printf("count: %d\n", count);
            count++;
            

        }
        
    }


    long int resultado = (((total2.tv_sec-total1.tv_sec) * 1000000) + (total2.tv_usec-total1.tv_usec))/qtd_pacotes;
    printf("Tempo de RECEBIMENTO MEDIO = %ld microssegundos\n",resultado);
    printf("Qtd de pacotes recebidos: %d\n", x);
    printf("Qtd de pacotes GOOSE recebidos: %d\n", y);
    printf("\n====================  FIM!  ====================\n\n");

	close(sockfd);
	return 0;
}

void imprimeHex(char *msg, int tamanho){
    if(tamanho == 0) return;
    if(tamanho--%4==0)printf(" ");
    printf("%02hhX", *msg);
    imprimeHex(++msg, tamanho);
    if(tamanho == 0) printf("\n");
}

char *geraHash(char *texto, int tamanho){
    char *buf = malloc(SHA256_BLOCK_SIZE);
    SHA256_CTX ctx;

    sha256_init(&ctx);
	sha256_update(&ctx, texto, tamanho);
	sha256_final(&ctx, buf);

	return buf;
}


char *geraDecifraRSA(char *texto, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho){
    gcry_error_t err;

    /* Create a message. */
    gcry_mpi_t msg;
    gcry_sexp_t data;
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, (const unsigned char*) texto, tamanho, NULL);
    if (err) xerr("failed to create a mpi from the message");

    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %M))", msg);
    if (err) xerr("failed to create a sexp from the message");

    /* Encrypt the message. */
    gcry_sexp_t ciph;
    err = gcry_pk_encrypt(&ciph, data, pub_key);
    if (err) xerr("gcrypt: encryption failed");
    //limpeza
    gcry_mpi_release(msg);
    gcry_sexp_release(data);

    gcry_mpi_t saida = gcry_sexp_nth_mpi(ciph, 0, GCRYMPI_FMT_USG);
    char *resposta = malloc(64);
    for(int i=0; i<32; i++) resposta[i] == 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) resposta, 32, NULL, saida);
    if (err) xerr("falha ao criar string mpi\n");

    return resposta;
}


