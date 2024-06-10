
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef struct tcpdata {
    u_int32_t td_end;
    u_int32_t td_maxend;
    u_short td_maxwin;
} tcpdata_t;

typedef struct tcpstate {
    u_short ts_sport;
    u_short ts_dport;
    tcpdata_t ts_data[2];
    u_char ts_state[2];
} tcpstate_t;

#define IPF_TCPS_CLOSED         0
#define IPF_TCPS_LISTEN         1
#define IPF_TCPS_SYN_SENT       2
#define IPF_TCPS_SYN_RECEIVED   3
#define IPF_TCPS_ESTABLISHED    4
#define IPF_TCPS_FIN_WAIT_1     5
#define IPF_TCPS_FIN_WAIT_2     6
#define IPF_TCPS_TIME_WAIT      7

#define MAX_STATES 1024
#define MAXACKWINDOW 66000

tcpstate_t *state_table[MAX_STATES] = {NULL};

unsigned int hash_func(struct in_addr src, struct in_addr dst, u_short sport, u_short dport) {
    return (src.s_addr ^ dst.s_addr ^ sport ^ dport) % MAX_STATES;
}

void add_state(tcpstate_t *state) {
    unsigned int hash = hash_func(*(struct in_addr *)&state->ts_data[0].td_end,
                                  *(struct in_addr *)&state->ts_data[1].td_end,
                                  state->ts_sport, state->ts_dport);
    state_table[hash] = state;
}

tcpstate_t* find_state(struct in_addr src, struct in_addr dst, u_short sport, u_short dport) {
    unsigned int hash = hash_func(src, dst, sport, dport);
    return state_table[hash];
}

void remove_state(tcpstate_t *state) {
    unsigned int hash = hash_func(*(struct in_addr *)&state->ts_data[0].td_end,
                                  *(struct in_addr *)&state->ts_data[1].td_end,
                                  state->ts_sport, state->ts_dport);
    state_table[hash] = NULL;
    free(state);
}

#define SEQ_GT(a, b) ((int)((a) - (b)) > 0)
#define SEQ_GE(a, b) ((int)((a) - (b)) >= 0)

void initialize_state(tcpstate_t *state, struct ip *ip, struct tcphdr *tcp) {
    state->ts_data[0].td_end = ntohl(tcp->th_seq) + ip->ip_len - (ip->ip_hl << 2) - (tcp->th_off << 2) + ((tcp->th_flags & TH_SYN) ? 1 : 0) + ((tcp->th_flags & TH_FIN) ? 1 : 0);
    state->ts_data[0].td_maxend = state->ts_data[0].td_end;
    state->ts_data[1].td_end = 0;
    state->ts_data[1].td_maxend = 0;
    state->ts_data[1].td_maxwin = 1;
    state->ts_data[0].td_maxwin = ntohs(tcp->th_win);
    if (state->ts_data[0].td_maxwin == 0)
        state->ts_data[0].td_maxwin = 1;
    state->ts_state[0] = IPF_TCPS_LISTEN;
    state->ts_state[1] = IPF_TCPS_LISTEN;
}

int check_seq_ack(tcpstate_t *state, struct tcphdr *tcp) {
    u_int32_t seq = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    int dir = 0; // 0 for original direction, 1 for reverse

    if (seq < state->ts_data[dir].td_end || seq > state->ts_data[dir].td_maxend) {
        printf("seq: %u, state->ts_data[dir].td_end %u, state->ts_data[dir].td_maxend %u \n", seq, state->ts_data[dir].td_end,state->ts_data[dir].td_maxend);
        return 0; // Invalid sequence number
    }
    if (ack && (ack < state->ts_data[1-dir].td_end || ack > state->ts_data[1-dir].td_maxend)) {
        printf("ack: %u, state->ts_data[1-dir].td_end %u, state->ts_data[1-dir].td_maxend %u \n", ack, state->ts_data[1-dir].td_end,state->ts_data[1-dir].td_maxend);
        return 0; // Invalid acknowledgment number
    }
    return 1; // Valid sequence and acknowledgment numbers
}

void tcp_state_transition(tcpstate_t *state, struct tcphdr *tcp, struct ip *ip) {
    u_int32_t seq = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_short win = ntohs(tcp->th_win);
    u_int32_t end = seq + ip->ip_len - (ip->ip_hl << 2) - (tcp->th_off << 2) + ((tcp->th_flags & TH_SYN) ? 1 : 0) + ((tcp->th_flags & TH_FIN) ? 1 : 0);
    tcpdata_t *fdata, *tdata;
    int source = (ip->ip_src.s_addr == state->ts_sport);

    fdata = &state->ts_data[!source];
    tdata = &state->ts_data[source];

    if (fdata->td_end == 0) {
        fdata->td_end = end;
        fdata->td_maxwin = 1;
        fdata->td_maxend = end + 1;
    }

    if (!(tcp->th_flags & TH_ACK)) {
        ack = tdata->td_end;
    } else if (((tcp->th_flags & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST)) && (ack == 0)) {
        ack = tdata->td_end;
    }

    if (seq == end)
        seq = end = fdata->td_end;

    int maxwin = tdata->td_maxwin;
    int ackskew = tdata->td_end - ack;

    if ((SEQ_GE(fdata->td_maxend, end)) &&
        (SEQ_GE(seq, fdata->td_end - maxwin)) &&
        (ackskew >= -MAXACKWINDOW) &&
        (ackskew <= MAXACKWINDOW)) {

        if (ackskew < 0)
            tdata->td_end = ack;

        if (fdata->td_maxwin < win)
            fdata->td_maxwin = win;

        if (SEQ_GT(end, fdata->td_end))
            fdata->td_end = end;
    }
}

void process_packet(struct ip *iph, struct tcphdr *tcp) {
    struct in_addr src = iph->ip_src;
    struct in_addr dst = iph->ip_dst;
    u_short sport = ntohs(tcp->th_sport);
    u_short dport = ntohs(tcp->th_dport);
    
    tcpstate_t *state = find_state(src, dst, sport, dport);
    if (state == NULL) {
        state = (tcpstate_t *)malloc(sizeof(tcpstate_t));
        memset(state, 0, sizeof(tcpstate_t));
        state->ts_sport = sport;
        state->ts_dport = dport;
        initialize_state(state, iph, tcp);
        add_state(state);
    }
    
    if (!check_seq_ack(state, tcp)) {
        printf("Invalid sequence or acknowledgment number\n");
        return; // Drop the packet
    }

    tcp_state_transition(state, tcp, iph);
}

int main() {
    // Example: process a packet (in a real application, this would be part of a packet processing loop)
    struct ip iph;
    struct tcphdr tcph;

    // Populate the packet with example data (this would come from the network in a real application)
    iph.ip_src.s_addr = inet_addr("192.168.0.1");
    iph.ip_dst.s_addr = inet_addr("192.168.0.2");
    tcph.th_sport = htons(12345);
    tcph.th_dport = htons(80);
    tcph.th_flags = TH_SYN;
    tcph.th_win = htons(65535);
    tcph.th_seq = htonl(57000);
    tcph.th_seq = htonl(57000);


    process_packet(&iph, &tcph);

    return 0;
}
