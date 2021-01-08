#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/stdio.h"

typedef int pid_t;
int p = 3;

static void syscall_handler (struct intr_frame *);
void halt();
pid_t exec(const char*cnd_line);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void*buffer, unsigned size);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void check_memory(const void *);
int fibonacci(int num);
int max_of_four_int(int*ptr);

struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sysnum = *((int*)f->esp), fd = 0, num = 0;
  int *ptr = NULL;
  const void *buf = NULL;
  uint32_t size = 0;

  //hex_dump(f->esp, f->esp, 50, 1);
  //printf ("check f->esp %d\n",is_kernel_vaddr(f->esp));
  check_memory(f->esp + 4);
  //printf ("asdf\n");
  switch (sysnum){
	case SYS_HALT:
	  halt();
	case SYS_EXIT:
    p = 5;
	  exit(*(int*)(f->esp + 4));
	  break;
	case SYS_EXEC:
	  f->eax = exec((char*)*(uint32_t*)(f->esp + 4));
	  break;
	case SYS_WAIT:
	  f->eax = wait(*((pid_t*)(f->esp + 4)));
	  break;
	case SYS_CREATE:
	  f->eax = create((char*)*(uint32_t*)(f->esp + 4), *(uint32_t*)(f->esp + 8));
	  break;
	case SYS_REMOVE:
	  f->eax = remove((char*)*(uint32_t*)(f->esp + 4));
	  break;
	case SYS_OPEN:
	  f->eax = open((char*)*(uint32_t*)(f->esp + 4));
	  break;
	case SYS_FILESIZE:
	  f->eax = filesize(*(uint32_t*)(f->esp + 4));
	  break;
	case SYS_READ:
	  fd = *((int*)(f->esp + 4));
	  buf = (void*)*(uint32_t*)(f->esp + 8);
	  size = *((uint32_t*)(f->esp + 12));
	  f->eax = read(fd, buf, size); 
	  break;
	case SYS_WRITE:
	  fd = *((int*)(f->esp + 4));
	  buf = (void*)*(uint32_t*)(f->esp + 8);
	  size = *((uint32_t*)(f->esp + 12));
	  f->eax = write(fd, buf, size);
	  break;
	case SYS_SEEK:
	  seek(*((int*)(f->esp + 4)), *(uint32_t*)(f->esp + 8));
	  break;
	case SYS_TELL:
	  f->eax = tell(*(int*)(f->esp + 4));
	  break;
	case SYS_CLOSE:
	  close(*(int*)(f->esp + 4));
	  break;
	case SYS_FIBONACCI:
	  num = *(int*)(f->esp + 4);
	  f->eax = fibonacci(num);
	  break;
	case SYS_MAX_OF_FOUR_INT:
	  ptr = (int*)(f->esp + 4);
	  f->eax = max_of_four_int(ptr);
	  break;
  }
}

void check_memory(const void *esp){
  p = 5;
  if (!is_user_vaddr(esp)) {
    exit(-1);
  }
}

void
halt(void){
  shutdown_power_off();
}

void
exit(int status){
  struct thread* t = thread_current();
  t->exit_code = status;
  printf ("%s: exit(%d)\n", t->name, status);

  for (int i = 3; i < MAX_FILE; i++) {
	  if (i > t->file_num) break;
	  if (t->file_desc[i] != NULL) close(i);
  }
  thread_exit();
}

pid_t exec (const char *cmd_line){
  return process_execute(cmd_line);
}

int wait (pid_t pid){
  return process_wait(pid);
}

int read (int fd, void *buffer, unsigned size){
  check_memory((void*) buffer);
  check_memory((void*) buffer + size -1);
  lock_acquire (&filesys_lock);
  int ret;
  void *temp = buffer;
  if (fd ==0) {
	for (int i = 0;i < size;i++){
	  *(uint8_t*)temp = input_getc();
	  temp = (uint8_t*)temp + 1;
	}
	ret = size;
  }
  else ret = file_read(thread_current()->file_desc[fd], buffer, size);
  lock_release (&filesys_lock);
  return ret;
}

int
write(int fd, const void*buffer, unsigned size){
  check_memory((void*) buffer);
  check_memory((void*) buffer + size -1);
  int ret;
  lock_acquire (&filesys_lock);
  if (fd == 1) {
	putbuf(buffer, size);
	ret = size;
  }
  else ret = file_write(thread_current()->file_desc[fd], buffer, size);
  lock_release (&filesys_lock);
  return ret;
}

bool
create (const char *file, unsigned initial_size) {
  if (file == NULL) exit(-1);
  lock_acquire (&filesys_lock);
  bool ret = filesys_create(file, initial_size);
  lock_release (&filesys_lock);
  return ret;
}

bool
remove (const char *file){
  if (file == NULL) exit(-1);
  lock_acquire (&filesys_lock);
  bool ret = filesys_remove(file);
  lock_release (&filesys_lock);
  return ret;
}

int
open (const char *file){
  int ret;
  if (file == NULL) exit(-1);
  lock_acquire (&filesys_lock);
  struct file* f_ptr = filesys_open(file);

  if (f_ptr == NULL) {
	lock_release(&filesys_lock);
	return -1;
  }

  struct thread* t = thread_current();
  t->file_num += 1;
  if (t->file_num >= MAX_FILE) {
	  for (int i = 3; i < MAX_FILE; i++){
		  if (t->file_desc[i] == NULL) {
			  t->file_num = i;
			  break;
		  }
	  }
  }
  if (strcmp(t->name, file) == 0) {
    file_deny_write(f_ptr);
  }
  t->file_desc[t->file_num] = f_ptr;
  lock_release (&filesys_lock);
  return t->file_num;
}

int
filesize (int fd){
  return file_length(thread_current()->file_desc[fd]);
}

void
seek (int fd, unsigned position){
  file_seek(thread_current()->file_desc[fd], (off_t)position);
}

unsigned
tell (int fd){
  off_t ret = file_tell(thread_current()->file_desc[fd]);
  return (unsigned)ret;
}

void
close (int fd){
  struct thread* t = thread_current();
  if (t->file_desc[fd] == NULL) exit(-1);
  file_close(t->file_desc[fd]);
  t->file_desc[fd] = NULL;
}

int fibonacci(int num){
  int f1 = 0, f2 = 1, temp;
  for(int i = 0; i < num; i++){
	  temp = f2;
	  f2 += f1;
	  f1 = temp;
  }
  return f1;
}

int max_of_four_int(int*ptr) {
  int t = 0, temp = 0;
  int nums[4] = {ptr[0], ptr[1], ptr[2], ptr[3]};
  t = nums[0];
  for (int j = 1; j < 4; j++) {
    if (nums[j] > t) {
	  temp = t;
	  t = nums[j];
	  nums[j] = temp;
	}
  }
  return t;
}