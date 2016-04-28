#ifndef LU_EXAMPLE_UTIL_H_
# define LU_EXAMPLE_UTIL_H_

typedef struct g_env_struct
{
  void *service_guid;
  int field_4;
  int field_8;
  cmd_info *commands_ptr;
  int commands_count;
  int unkn_1;
  int unkn_2;
  int nl_sock;
  int pipedes[2];
  int prog_id;
  pthread_mutex_t mutex_write;
  int unkn_3;
  int unkn_4;
} god_s __attribute__((packed));

typedef struct file
{
  int fd;
} file __attribute__((packed));

typedef struct lnx_msg_hdr
{
  int aligned_size;
  unsigned short type;
  unsigned short unkn;
  int field_8;
  int prog_id;
} lnx_msg_hdr __attribute__((packed));


typedef struct lnx_msg_element
{
  int cmd_id;
  int field_4;
  int field_8;
  int element_count;
  unsigned char payload[60];
  char end_pad_1;
  char end_pad_2;
  char end_pad_3;
  char unknown_pad;
} lnx_msg_element __attribute__((packed));

typedef struct cmd_info_msg
{
  void *func_ptr; //*
  int cmd_id; //*
  int field_C; //*
  int field_10; //*
  char payload[40];
} cmd_info_msg __attribute__((packed));

typedef struct cmd_info
{
  void *func_ptr; //*
  int cmd_id; //*
  int field_8;
  int field_C; //*
  int field_10; //*
  int field_14;
  int field_18;
  int field_1C;
  int field_20;
  int field_24;
  void *cmd_name;
} cmd_info __attribute__((packed));

struct shared_mem
{
  int field_0;
  int opened_file;
  char field_8;
  char field_9;
  char field_A;
  char field_B;
  char field_C;
  char field_D;
  char field_E;
  char field_F;
} __attribute__((packed));

#endif /* !LU_EXAMPLE_UTIL_H_ */
