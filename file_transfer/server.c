/*
Built on:
Architecture:        x86_64
Byte Order:          Little Endian
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#include "encrypt.h"

#define TIMEOUT 4
#define SESSION_TIMEOUT 4
#define MAX_THREADS 32
#define PACK_SIZE 4096
#define LOG_FILE "file_transfer.log"

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

// TODO valgrind for mem leaks

pthread_t threads[MAX_THREADS];
uint32_t threads_bitmask = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t free_t_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;
int fd;

//this is the session structure it's ip based so that it starts with UDP and then when a connection is received from the TCP it can relate it
// back with the right encryption and file storage server and right TCP port for the storage server
// I made it timeout after a certain amount of seconds but it "revitalize" when sending the file, so that it timesout only when it's done transfering
struct session {
	uint32_t from;
	time_t timestamp;
	unsigned short tcp_port;
	char encryption[255];
	char in_progress;
};

unsigned int nb_sessions = 100;
struct session* sessions;

struct request {
	socklen_t fromlen;
	struct sockaddr_in from;
	char buf[PACK_SIZE];
	int length;
	unsigned int thread_nb;
	int sock;
};

void
init_sessions()
{
	struct session s;
	int i;

	s.from = 1;
	s.timestamp = 0;
	strcpy(s.encryption, "");
	s.in_progress = 0;
	s.tcp_port = 0;
	sessions = calloc(sizeof(struct session),nb_sessions);
	for (i = 0; i < nb_sessions; i++) {
		sessions[i] = s;
	}
}

int
find_session(uint32_t from)
{
	int i;
	if (from == 0) return -1;

	pthread_mutex_lock(&session_mutex);
	for (i = 0; i < nb_sessions; i++) {
		if (sessions[i].from == from) {
			pthread_mutex_unlock(&session_mutex);
			return i;
		}
	}
	pthread_mutex_unlock(&session_mutex);
	return -1;
}

void
revitalize_session(uint32_t from)
{
	int i;
	time_t now = time(NULL);

	pthread_mutex_lock(&session_mutex);
	for (i = 0; i < nb_sessions; i++) {
		if (sessions[i].from == from) {
			sessions[i].timestamp = now;
			break;
		}
	}
	pthread_mutex_unlock(&session_mutex);
}

void
clear_session(uint32_t from)
{
	int i;

	pthread_mutex_lock(&session_mutex);
	for (i = 0; i < nb_sessions; i++) {
		if (sessions[i].from == from) {
			sessions[i].from = 1;
			sessions[i].timestamp = 0;
			sessions[i].in_progress = 0;
			sessions[i].tcp_port = 0;
			strcpy(sessions[i].encryption, "");
			break;
		}
	}
	pthread_mutex_unlock(&session_mutex);
}

int
add_session(uint32_t from, unsigned short port, char* encryption)
{
	unsigned int i;
	time_t now = time(NULL);
	pthread_mutex_lock(&session_mutex);

	// cleanup sessions but if there's any with the same ip then use it
	for (i = 0; i < nb_sessions; i++) {
		if (now - sessions[i].timestamp >= SESSION_TIMEOUT) {
			if (sessions[i].from == from) {
				strcpy(sessions[i].encryption, encryption);
				sessions[i].in_progress = 1;
				sessions[i].timestamp = now;
				sessions[i].tcp_port = port;
				pthread_mutex_unlock(&session_mutex);
				return i;
			} else {
				sessions[i].from = 0;
				sessions[i].timestamp = 0;
				sessions[i].in_progress = 0;
				sessions[i].tcp_port = 0;
				strcpy(sessions[i].encryption, "");
			}
		}
	}

	// first check if there's already a session with that ip
	for (i = 0; i < nb_sessions; i++) {
		// there's an ongoing session
		if (sessions[i].from == from) {
			pthread_mutex_unlock(&session_mutex);
			return -1;
		}
	}
	for (i = 0; i < nb_sessions; i++) {
		if (sessions[i].in_progress == 0) {
			sessions[i].from = from;
			strcpy(sessions[i].encryption, encryption);
			sessions[i].in_progress = 1;
			sessions[i].timestamp = now;
			sessions[i].tcp_port = port;
			pthread_mutex_unlock(&session_mutex);
			return i;
		}
	}
	pthread_mutex_unlock(&session_mutex);
	return -1;
}

unsigned int
get_free_thread()
{
	unsigned int i = 0;
	unsigned int free_thread = -1;
	pthread_mutex_lock(&free_t_mutex);
	for (i=0; i < 32; i++) {
		if (!CHECK_BIT(threads_bitmask, i)) {
			free_thread = i;
			threads_bitmask |= 1 << i;
			break;
		}
	}
	pthread_mutex_unlock(&free_t_mutex);
	return free_thread;
}

void
free_thread(unsigned int i)
{
	pthread_mutex_lock(&free_t_mutex);
	threads_bitmask &= 0 << i;
	pthread_mutex_unlock(&free_t_mutex);
}


char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
					s, maxlen);
			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
					s, maxlen);
			break;

		default:
			strncpy(s, "Unknown AF", maxlen);
			return NULL;
	}

	return s;
}

void
log_request_to_file(
	const char* from_str,
	int length,
	char pkt_type,
	char *ipv4_str,
	unsigned short port,
	unsigned short enc_len,
	char* enc_pattern,
	char* unenc_init)
{
	pthread_mutex_lock(&log_mutex);

	char log_data[4096];
	time_t now = time(NULL);
	char *_now_str = ctime(&now);
	char now_str[4096];
	strncpy(now_str, _now_str, strlen(_now_str)-1);
	sprintf(log_data,
"%s: Received request from: %s, with %d Bytes\
{ msg_type: '%d',\
ipv4: '%s',\
port: '%d',\
enc_len: '%d',\
enc_pattern: '%s',\
unenc_init: '%s'}\n"
		, now_str
		, from_str, length
		, pkt_type
		, ipv4_str
		, port
		, enc_len, enc_pattern
		, unenc_init);

	FILE *fp;
	fp = fopen(LOG_FILE, "a");
	puts(log_data);
	fprintf(fp, log_data);
	fclose(fp);
	pthread_mutex_unlock(&log_mutex);
}

void*
handle_tcp_request(void* pack)
{
	struct request *req = (struct request*)pack;
	int bytesReceived = 0;
	char recvBuff[256];
	char from_str[255];
	char* encrypted;
	int session;
	memset(recvBuff, '0', sizeof(recvBuff));

	get_ip_str((struct sockaddr *)&(req->from), from_str, 255);
	puts(from_str);

	// check if there's an ongoing session -> no close
	session = find_session(req->from.sin_addr.s_addr);
	printf("Session #%d\n", session);
	if (session < 0) {
		puts("NO SESSION");
		write(req->sock, "NO SESSION", 10);
		close(req->sock);
		pthread_exit(NULL);
		return NULL;
	}

	/* create a tcp client to the file storage */
	int sock_desc;
	struct sockaddr_in serv_addr;
	if((sock_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		printf("Failed creating socket\n");
	bzero((char *) &serv_addr, sizeof (serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = sessions[session].from;
	serv_addr.sin_port = htons(sessions[session].tcp_port);
	if (connect(sock_desc, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) {
		printf("Failed to connect to TCP on file storage\n");
		goto QUIT_TCP_THREAD;
	}

	/* Receive data in chunks of 256 bytes */
	while((bytesReceived = read(req->sock, recvBuff, 256)) > 0) {
		printf("Bytes received %d\n",bytesReceived);
		//printf("received: %s\n", recvBuff);
		write(req->sock, "ACK", 3);
		//printf("encryption of sessions is: %s\n", sessions[session].encryption);
		encrypted = encrypt(recvBuff, sessions[session].encryption, bytesReceived);
		revitalize_session(req->from.sin_addr.s_addr);
		send(sock_desc, encrypted, bytesReceived, 0);
	}
	if(bytesReceived < 0) {
		printf("\n[!]Read Error\n");
	}

	close(sock_desc);
	close(req->sock);

QUIT_TCP_THREAD:
	free(req);
	clear_session(req->from.sin_addr.s_addr);
	free_thread(req->thread_nb);
	pthread_exit(NULL);
}

void*
handle_udp_request(void* pack)
{
	struct timeval tv;
	struct request *req = (struct request*)pack;
	int padding = sizeof(char);
	char from_str[255];
	char ipv4_str[255];
	char buffer[4096];
	char pkt_type;
	unsigned int ipv4;
	unsigned int unenc_len;
	unsigned short port;
	unsigned short enc_len;
	char* enc_pattern = NULL;
	char* reply_enc = NULL;
	char* unenc_init = NULL;
	char* enc_init = NULL;
	char* decrypted = NULL;
	char *ft2fs = NULL;
	struct sockaddr_in server;
	int s;
	int sent_length;
	int session;

	if (req->length < 20) goto QUIT_UDP_THREAD;

	get_ip_str((struct sockaddr *)&(req->from), from_str, 255);

	memcpy(&pkt_type, req->buf, sizeof(char));
	if (pkt_type != 0x00) goto QUIT_UDP_THREAD;

	memcpy(&ipv4, req->buf+padding, sizeof(ipv4));
	inet_ntop(AF_INET, (struct sockaddr_in *)(&ipv4), ipv4_str, 255);
	padding += sizeof(ipv4);

	memcpy(&port, req->buf+padding, sizeof(unsigned short));
	padding += sizeof(unsigned short);

	memcpy(&enc_len, req->buf+padding, sizeof(unsigned short));
	padding += sizeof(unsigned short);

	enc_pattern = malloc(enc_len+1);
	memcpy(enc_pattern, req->buf+padding, enc_len);
	enc_pattern[enc_len] = '\0';
	padding += enc_len;

	unenc_len = req->length - padding;

	unenc_init = malloc(unenc_len+1);
	memcpy(unenc_init, req->buf+padding, unenc_len);
	unenc_init[unenc_len] = '\0';
	padding += unenc_len;

	log_request_to_file(from_str, req->length, pkt_type, ipv4_str, port, enc_len, enc_pattern, unenc_init);
	enc_init = encrypt(unenc_init, enc_pattern, strlen(unenc_init));
	enc_init[strlen(unenc_init)] = '\0';

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset((char *) &server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if (inet_aton(ipv4_str, &server.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed\n");
		return NULL;
	}

	ft2fs = malloc(strlen(enc_init)+2);
	ft2fs[0] = 0x01;
	strcpy(ft2fs+1, enc_init);

	sent_length = sendto(
		s,
		ft2fs,
		strlen(ft2fs),
		0,
		(const struct sockaddr *)&server,
		sizeof(struct sockaddr_in)
	);

	sent_length = sizeof(struct sockaddr_in);
	tv.tv_sec = TIMEOUT;  /* 15 Secs Timeout */
	tv.tv_usec = 0;  // Not init'ing this can cause strange errors
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,sizeof(struct timeval));
	req->length = recvfrom(
		s,
		buffer,
		4096,
		0,
		(struct sockaddr *)&server,
		(socklen_t *)&sent_length
	);
	if (req->length < 0) {
		decrypted = malloc(30);
		strcpy(decrypted, "ERROR: storage doesn't reply");
		clear_session(req->from.sin_addr.s_addr);
	} else {
		memcpy(&pkt_type, buffer, sizeof(char));
		padding = 1;
		memcpy(&port, buffer+padding, sizeof(unsigned short));
		padding += sizeof(unsigned short);
		reply_enc = malloc(req->length - padding);
		memcpy(reply_enc, buffer+padding, req->length-padding);
		decrypted = decrypt(reply_enc, enc_pattern, strlen(reply_enc));
		decrypted[strlen(decrypted)-1] = '\0';
		// ignore the "ACK:" and see if it still fits
		// check if there's already an ongoing session
		session = add_session(req->from.sin_addr.s_addr, port, enc_pattern);
		if (session < 0) {
			strcpy(buffer, "ERROR: Session already ongoing");
			sent_length = sendto(
				fd,
				buffer,
				strlen(buffer),
				0,
				(const struct sockaddr *)&req->from,
				req->fromlen
			);
			printf("sent back %dBytes\n", sent_length);
		}

		if (strncmp(decrypted+4,unenc_init, strlen(unenc_init)) == 0) {
			puts("ACK successful!");
		}
	}

	ft2fs = realloc(ft2fs, strlen(decrypted)+2);
	ft2fs[0] = 0x03;
	strcpy(ft2fs+1, decrypted);

	sent_length = sendto(
		fd,
		ft2fs,
		strlen(decrypted)+1,
		0,
		(const struct sockaddr *)&req->from,
		req->fromlen
	);

	printf("sent back %dBytes\n", sent_length);

	if (enc_init) {
		free(enc_init);
	}
	if (enc_pattern) {
		free(enc_pattern);
	}
	if (unenc_init) {
		free(unenc_init);
	}
	if (ft2fs) {
		free(ft2fs);
	}
	if (decrypted) {
		free(decrypted);
	}

QUIT_UDP_THREAD:
	free_thread(req->thread_nb);
	free(req);
	pthread_exit(NULL);
}

void*
udp_service(void *p)
{
	puts("UDP SERVICE STARTED");
	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror( "socket failed" );
		return NULL;
	}

	struct sockaddr_in serveraddr;
	memset( &serveraddr, 0, sizeof(serveraddr) );
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons( 16001 );
	serveraddr.sin_addr.s_addr = htonl( INADDR_ANY );

	if ( bind(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
		perror( "bind failed" );
		return NULL;
	}

	int rc = 0;
	while (1) {
		struct request *req = malloc(sizeof(struct request));
		req->fromlen = sizeof(struct sockaddr_in);
		req->length = recvfrom( fd, req->buf, PACK_SIZE, 0, (struct sockaddr *)&req->from, &req->fromlen );
		if ( req->length < 0 ) {
			perror( "recvfrom failed" );
			break;
		}
		req->thread_nb = get_free_thread();
		rc = pthread_create(&threads[req->thread_nb], NULL, handle_udp_request, (void*)req);
		if(rc){
			printf("A request could not be processed\n");
		}
	}

	close( fd );
	pthread_exit(NULL);
	return NULL;
}

void*
tcp_service(void *p)
{
	puts("TCP SERVICE STARTED");
	int listenfd = 0;

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		perror("tcp socket failed");
		return NULL;
	}

	struct sockaddr_in serveraddr;
	memset( &serveraddr, 0, sizeof(serveraddr) );
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons( 17001 );
	serveraddr.sin_addr.s_addr = htonl( INADDR_ANY );

	if (bind(
		listenfd,
		(struct sockaddr *)&serveraddr,
		sizeof(serveraddr)) < 0 ) {
		perror( "bind failed" );
		return NULL;
	}
	if(listen(listenfd, 3) == -1)
	{
		printf("Failed to listen to TCP\n");
		exit(1);
	}

	int rc = 0;
	while (1) {
		// here start a thread with connfd
		struct request *req = malloc(sizeof(struct request));

		req->fromlen = sizeof(struct sockaddr_in);
		req->sock = accept(listenfd, (struct sockaddr*)&req->from, &req->fromlen);
		req->thread_nb = get_free_thread();
		rc = pthread_create(&threads[req->thread_nb], NULL, handle_tcp_request, (void*)req);
		if (rc) {
			printf("A request could not be processed\n");
		}
	}

	close(listenfd);
	pthread_exit(NULL);
	return NULL;
}

int
main(int argc, char** argv)
{
	int rc;
	pthread_t udp_thread;
	pthread_t tcp_thread;
	init_sessions();

	rc = pthread_create(&udp_thread, NULL, udp_service, NULL);
	if(rc){
		printf("UDP service couldn't start");
		exit(1);
	}
	rc = pthread_create(&tcp_thread, NULL, tcp_service, NULL);
	if(rc){
		printf("TCP service couldn't start");
		exit(1);
	}
	pthread_join(udp_thread, NULL);
	pthread_join(tcp_thread, NULL);
	return 0;
}
