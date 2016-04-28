#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>

#include "lu_example_util.h"

#define ERR(x) do { \
  perror("Error(" x ") in " __FUNCTION__ " at " __FILE__ "(l " __LINE__ ")"); \
} while (0)

#define bailout(retn) do { \
  perror("Error in " __FUNCTION__ " at " __FILE__ "(l " __LINE__ ")"); \
  return (retn); \
} while (0)

god_s g_god;
fd_set readfds_god;

void init_god_struct(god_s *god)
{
  int ret;

  god->unkn_1 = NULL;
  god->unkn_2 = NULL;
  god->unkn_3 = NULL;
  god->unkn_4 = NULL;
  god->nl_sock = -1;
  if ((ret = init_prog(god)) < 0)
    bailout(ret);
  god->unkn_1 = 1;

  pthread_mutex_init(&god->mutex_write, NULL);
  FD_ZERO(&readfds_god);
}

int init_prog(god_s *god)
{
  int *p_des;
  int ret;
  int n_elts;
  size_t total_size;
  void *msg_lme;
  lnx_msg_element *msg_tmp;

  p_des = &god->pipedes;
  if ((ret = pipe(p_des)) < 0)
    bailout(ret);

  if ((ret = init_netlink(&god->nl_sock, &god->prog_id)) < 0)
    bailout(ret);

  n_elts = god->commands_count + 1;
  total_size = n_elts * sizeof(*msg_lme) + sizeof(lnx_msg_hdr);
  if ((msg_lme = malloc(total_size) == NULL))
    bailout(-1);

  set_lnx_hdr(msg_lme, god->prog_id, n_elts * sizeof(msg_lme), 1);
  init_register_func(god, msg_lme, n_elts * sizeof(*msg_lme));
  if (send_netlink_msg(god, msg_lme) < 0)
  {
    ERR("send message failed");
    free(msg_lme);
    return -1;
  }
  memset(msg_lme, 0, total_size);
  if (recv_netlink_msg(god, msg_lme, total_size) < 0)
  {
    ERR("receive message failed");
    free(msg_lme);
    return -1;
  }

  msg_tmp = msg_lme + (void*)0x10;

  if (msg_tmp->cmd_id != 1)
  {
    printf("Register prog fail: %d\n", msg_tmp->cmd_id);
    free(msg_lme);
    return -1;
  }
  free(msg_lme);
  return 0;
}

int recv_netlink_msg(struct g_env_strct *god, struct lnx_msg_element *msg_lme, size_t size)
{
  struct msghdr msg;
  struct iovec iov_buf;

  memset(&msg, 0, sizeof(msg));

  iov_buf.iov_base = msg_lme;
  iov_buf.iov_len = size;

  msg.msg_iov = &iov_buf;
  msg.msg_iovlen = 1;

  return recvmsg(god->nl_sock, &msg, 0);
}

int send_netlink_msg(struct g_env_strct *god, struct lnx_msg_element *msg_lme)
{
  struct msghdr msg;
  struct iovec iov_buf;
  lnx_msg_hdr *lme_hdr;
  char msgname[0xc];

  memset(msgname, 0, sizeof(msgname));
  memset(&msg, 0, sizeof(msg));

  lme_hdr = (lnx_msg_hdr*)msg_lme;
  iov_buf.iov_base = msg_lme;
  iov_buf.iov_len = lme_hdr->aligned_size;

  msg.msg_iov = &iov_buf;
  msg.msg_iovlen = 1;
  msg.msg_name = msgname;
  msg.msg_namelen = sizeof(msgname);

  return sendmsg(god->nl_sock, &msg, 0) < 0 ? -1 : 0;
}

void init_register_func(struct g_env_struct *god, void *msg_lme, size_t elts_size)
{
  lnx_msg_element *tmp_msg;
  cmd_info_msg *tmp_cmd;
  unsigned char *buf;
  size_t prog_name_len, func_name_len;
  int i;

  tmp_msg = msg_lme + (void *)0x10;

  tmp_msg->cmd_id = god->prog_id;
  tmp_msg->field_4 = god->field_4;
  tmp_msg->field_8 = god->field_8;
  tmp_msg->element_count = god->commands_count;
  memset(tmp_msg->payload, 0, 0x40);

  if ((prog_name_len = strlen(god->service_guid)) < 0x40)
    memcpy(tmp_msg->payload, god->service_guid, prog_name_len);
  else
  {
    memcpy(tmp_msg->payload, god->service_guid, 0x3c);
    memset(tmp_msg->payload + 0x3c, 0x2e, 3);
  }

  for (i = 0; i < god->commands_count; i++)
  {
    tmp_msg++;
    tmp_cmd = (cmd_info_msg*)tmp_msg;
    tmp_cmd->func_ptr = god->commands_ptr[i + 1].func_ptr;
    tmp_cmd->cmd_id = god->commands_ptr[i + 1].cmd_id;
    tmp_cmd->field_C = god->commands_ptr[i + 1].field_C;
    tmp_cmd->field_10 = god->commands_ptr[i + 1].field_10;
    memset(&tmp_cmd->payload, 0, 0x40);
    if ((func_name_len = strlen(god->commands_ptr[i + 1].cmd_name)) < 0x40)
      memcpy(tmp_msg->payload, );
    else
    {
      memcpy(tmp_msg->payload, god->commands_ptr[i + 1].cmd_name, 0x3c);
      memset(tmp_msg->payload + 0x3c, 0x2e, 3);
    }
  }
}

inline void set_lnx_hdr(lnx_msg_hdr *hdr, int prog_id,
                        size_t elts_size, unsigned short msg_type)
{
  int r12 = 0;

  elts_size += 0x13;
  elts_size &= ~0x3;

  hdr->unkn = 0;
  hdr->aligned_size = elts_size;
  hdr->prog_id = prog_id;
  hdr->type = msg_type;
}

int init_netlink(int *fd, int *prog_id)
{
  int ret;
  struct sockaddr_nl nl_addr;

  memset(&nl_addr, 0, sizeof(nl_addr));
  if ((*fd = socket(0x10 /* AF_NETLINK */, 0x2 /* NETLINK_USERSOCK */, 0x19)) < 0)
    bailout(-1);

  nl_addr.nl_family = AF_NETLINK;
  nl_addr.nl_groups = 0;
  nl_addr.nl_pid = get_prog_id();
  if ((ret = bind(*fd, &nl_addr, sizeof(nl_addr)) < 0))
    bailout(ret);

  return 0;
}

pid_t get_prog_id()
{
  int fd;
  pthread_t pid_pt;
  pid_t pid;
  char buf[10];

  pid_pt = pthread_self();
  pid = getpid();

  pid += pid_pt << 16;
  if ((fd = open("/proc/aipc/lu_prog_id", O_RDONLY)) < 0)
  {
    close(fd);
    return pid;
  }
  memset(buf, 0, sizeof (buf));
  if (read(fd, buf, 8) < 8)
  {
    close(fd);
    return pid;
  }
  sscanf(buf, "%x", &pid);

  return pid;
}

void sig_handler(int sig)
{
  fprintf(STDERR, "Caught signal %d\n", sig);
  exit(0);
}

int receive_svcxrpt_userland(god_s *god, struct lnx_msg_element *msg_lme)
{
  memset(msg_lme, 0, 0x4038);
  if (recv_netlink_msg(god, msg_lme, 0x4038) < 0)
  {
    ERR("receive svcxrpt from kernel failed");
    return -1;
  }

  return 0;
}

int ipc_svc_poll_prog(god_s *god, int timeout)
{
  int n, ret;
  fd_set readfs;
  struct timeval timeout_tv;

  if (god == NULL || god->unkn_2 != 0)
    return -1;

  FD_ZERO(&readfs);
  FD_SET(god->nl_sock, &readfs);
  FD_SET(god->pipedes[0], &readfs);
  timeout_tv.tv_sec = timeout;

  n = god->nl_sock < god->pipedes[0] ? god->pipedes[0] : god->nl_sock;
  if ((ret = select(n + 1, &readfs, NULL, NULL, &timeout_tv) < 0))
    bailout(-1);
  if (FD_ISSET(god->nl_sock, &readfs))
  {
  } else if (FD_ISSET(god->pipedes[0], &readfs))
  {
  }
    /*TODO*/
}

int main(int argc, char *argv[])
{
  signal(SIGHUP,  sig_handler);
  signal(SIGINT,  sig_handler);
  signal(SIGTERM, sig_handler);
  //TODO init god structure
  init_god_struct(&g_god);
  while (!(ipc_svc_poll_prog(&g_god, 0) < 0));
  return 0;
}
