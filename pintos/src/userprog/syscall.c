#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

struct list process_info_list;
struct list file_info_list;
static struct lock pil_lock;
static struct lock fil_lock;

struct process_info* get_process_info(tid_t pid) {
  struct list_elem *e;

  struct process_info* pi = NULL;
  lock_acquire(&pil_lock);
  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
  {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        pi = p;
        break;
      }
  }

  lock_release(&pil_lock);

  return pi;
}

void add_process_to_list(const char* name, tid_t tid) {
  struct process_info *pi  = (struct process_info*) malloc (sizeof(struct process_info));
  pi->exit_code = -1000;
  pi->pid = tid;
  memcpy(pi->name, name, strlen(name)+1);

  lock_acquire(&pil_lock);
  list_push_back(&process_info_list, &pi->elem);
  lock_release(&pil_lock);
}

void delete_process_from_list(tid_t pid) {
  struct list_elem *e;

  struct process_info* pi = NULL;
  lock_acquire(&pil_lock);
  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
  {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
	list_remove(&p->elem);
        break;
      }
  }

  lock_release(&pil_lock);

  return pi;
}

void set_process_exitcode(tid_t pid, int exit_code) {
  struct list_elem *e;

  lock_acquire(&pil_lock);

  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
    {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        p->exit_code = exit_code;
        break;
      }
    }

  lock_release(&pil_lock);
}


struct file_info* get_file_info(int fd) {
  struct list_elem *e;

  struct file_info* fi = NULL;
  for (e = list_begin (&file_info_list); e != list_end (&file_info_list);
       e = list_next (e))
  {
      struct file_info *f = list_entry (e, struct file_info, elem);
      if (f->fd == fd) {
        fi = f;
        break;
      }
  }

  return fi;
}

struct file_info* get_file_info_fid(char* fid) {
  struct list_elem *e;

  struct file_info* fi = NULL;
  for (e = list_begin (&file_info_list); e != list_end (&file_info_list);
       e = list_next (e))
  {
      struct file_info *f = list_entry (e, struct file_info, elem);
      if (f->fid == fid) {
        fi = f;
        break;
      }
  }

  return fi;
}

int add_file_to_list(struct file *file) {
  struct file_info *fi = (struct file_info*) malloc(sizeof(struct file_info));
  fi->fid = file;
  fi->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back (&file_info_list, &fi->elem);
  return fi->fd;
}

void close_and_delete_files(int fd) {
  struct list_elem *e;
  for (e = list_begin (&file_info_list); e != list_end (&file_info_list); e = list_next (e)) {
    struct file_info *fi = list_entry (e, struct file_info, elem);
    if (fd == fi->fd || fd == -1) {
      file_close(fi->fid);
      list_remove(&fi->elem);
      free(fi);
      if (fd != -1) {
        return;
      }
    }
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&process_info_list);
  list_init(&file_info_list);
  lock_init(&pil_lock);
  lock_init(&fil_lock);
}

bool check_ptr(void* ptr) {
  struct thread* t = thread_current();
  if ( !is_user_vaddr (ptr) || pagedir_get_page(t->pagedir, ptr) == NULL) {
    return false;
  }
  return true;
}

void exit(int exit_code) {
  set_process_exitcode(thread_current()->tid, exit_code);
  struct process_info* pi = get_process_info(thread_current()->tid) ;

  printf("%s: exit(%d)\n", pi->name , exit_code);
  thread_exit();
} 

void exec(struct intr_frame *f, int* esp) {
  if (!check_ptr(*(esp+1))) {
    exit(-1);
    return;
  }
  
  char* name = *(esp + 1);
  
  if (strlen(name) == 0) {
    f->eax = -1;
    return;
  }
  
  char *save_ptr1;
  char* filename_copy = palloc_get_page(0);
  strlcpy (filename_copy, name, PGSIZE);
  char *exename = strtok_r (filename_copy, " ", &save_ptr1);
  struct file *file = filesys_open(exename);
  if(file == NULL){
    f->eax = -1;
  }
  else {
   file_close(file);
   f->eax = process_execute(name);
  }
}

void wait(struct intr_frame *f, int*esp) {
  if (!check_ptr(esp+1)) {
    exit(-1);
    return;
  }

  tid_t pid = *(esp + 1);

  f->eax = process_wait(pid);
}

void create(struct intr_frame *f, int* esp) {
  if (!check_ptr(*(esp+1)) || !check_ptr(esp+2)) {
    exit(-1);
    return;
  }

  const char *file = *(esp+1);
  unsigned int file_size = *(esp+2);

  f->eax = filesys_create(file, file_size);
}

void remove(struct intr_frame *f, int* esp) {
  if (!check_ptr(*(esp+1))) {
    exit(-1);
    return;
  }

  const char *file = *(esp+1);

  f->eax = filesys_remove(file);
}

void open(struct intr_frame *f, int* esp) {
  if (!check_ptr(*(esp+1))) {
    exit(-1);
    return;
  }

  const char *file_name = *(esp+1);

  struct file* file = filesys_open(file_name);
  if (file == NULL) {
    f->eax = -1;
  }
  else {
    lock_acquire(&fil_lock);
    int fd = add_file_to_list(file);
    lock_release(&fil_lock);
    f->eax = fd;
  }
}

void filesize (struct intr_frame *f, int* esp) {
  if (!check_ptr(esp+1) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);

  lock_acquire(&fil_lock);
  struct file_info* fi = get_file_info(fd);
  if (fi == NULL) {
    lock_release(&fil_lock);
    f->eax = -1;
  }
  else {
    int len = file_length(fi->fid);
    lock_release(&fil_lock);
    f->eax = len;
  }
}

void read(struct intr_frame *f, int* esp) {
  if (!check_ptr(esp+1) || !check_ptr(*(esp+2)) || !check_ptr(esp+3)) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = *(esp + 2);
  int len = *(esp + 3);

  if (fd == 0) {
    f->eax = len;
  }
  else {
    lock_acquire(&fil_lock);
    struct file_info *fi = get_file_info(fd);
    if (!fi) {
      lock_release(&fil_lock);
      f->eax = -1;
    }
    else {
      int bytes_read = file_read(fi->fid, buffer, len);
      lock_release(&fil_lock);
      f->eax = bytes_read;
    }
  }
}

void write(struct intr_frame *f, int* esp) {
  if (!check_ptr(esp+1) || !check_ptr(*(esp+2)) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = *(esp + 2);
  unsigned int len = *(esp + 3);

  if (fd == STDIN_FILENO) {
    exit(-1);
    return;
  }
  else if (fd == STDOUT_FILENO) {
    putbuf(buffer, len);
    f->eax = len;
  }
  else {
    lock_acquire(&fil_lock);
    struct file_info *fi = get_file_info(fd);
    if (fi == NULL) {
      lock_release(&fil_lock);
      f->eax = -1;
    }
    else {
      int bytes_written = file_write(fi->fid, buffer, len);
      lock_release(&fil_lock);
      f->eax = bytes_written;
    }
  }
}

void seek(struct intr_frame *f, int* esp) {
  if (!check_ptr(esp+1) || !check_ptr(esp+2)) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  unsigned position = *(esp + 2);

  lock_acquire(&fil_lock);
  struct file *file = get_file_info(fd)->fid;
  file_seek(file, position);
  lock_release(&fil_lock);
}

void tell(struct intr_frame *f, int* esp) {
  if (!check_ptr(esp+1)) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  
  lock_acquire(&fil_lock);
  struct file *file = get_file_info(fd)->fid;
  file_tell(file);
  lock_release(&fil_lock);
}

void close(struct intr_frame *f, int* esp) {
  if (!check_ptr(esp+1)) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);

  if (fd == STDIN_FILENO) {
    exit(-1);
    return;
  }
  else if (fd == STDOUT_FILENO) {
    exit(-1);
    return;
  }

  close_and_delete_files(fd);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* esp = f->esp;
 
  if ( !check_ptr(esp)) {
    exit(-1);
    return;
  }

  int number = *esp;
  if (number == 0) {
    shutdown_power_off();
  }
  else if (number == 1) {
    if ( !check_ptr(esp+1) ) {
      exit(-1);
      return;
    }
    int exit_code = *(esp+1) ;
    exit(exit_code);
  }
  else if (number == SYS_EXEC) {
    exec(f, esp);
  }
  else if (number == SYS_WAIT) {
   wait(f, esp);
  }
  else if (number == SYS_CREATE) {
   create(f, esp);
  }
  else if (number == SYS_REMOVE) {
   remove(f, esp);
  }
  else if (number == SYS_OPEN) {
   open(f, esp);
  }
  else if (number == SYS_FILESIZE) {
   filesize(f, esp);
  }
  else if (number == SYS_READ) {
    read(f, esp);
  }
  else if (number == SYS_WRITE) {
    write(f, esp);
  }
  else if (number == SYS_SEEK) {
    seek(f, esp);
  }
  else if (number == SYS_TELL) {
    tell(f, esp);
  }
  else if (number == SYS_CLOSE) {
    close(f, esp);
  }
}
