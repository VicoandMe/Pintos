#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* add */
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"
/*eadd */

static void syscall_handler (struct intr_frame *);

/* add */

typedef int pid_t;

static int sys_write (int fd, const void *buffer, unsigned length);
static int sys_halt (void);
static int sys_create (const char *file, unsigned initial_size);
static int sys_open (const char *file);
static int sys_close (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_exec (const char *cmd);
static int sys_wait (pid_t pid);
static int sys_filesize (int fd);
static int sys_tell (int fd);
static int sys_seek (int fd, unsigned pos);
static int sys_remove (const char *file);

static struct file *find_file_by_fd (int fd);
static struct fd_elem *find_fd_elem_by_fd (int fd);
static int alloc_fid (void);
static struct fd_elem *find_fd_elem_by_fd_in_process (int fd);

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_vec[128];
static struct lock file_lock;

struct fd_elem
  {
    int fd;
    struct file *file;
    struct list_elem elem;
    struct list_elem thread_elem;
  };
  
static struct list file_list;

/* add */
/*
 * Reads a byte at user virtual address UADDR.
 * UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred.
 * */
static int
get_user (const uint8_t *uaddr) {
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
		: "=&a"  (result)
		: "m" (*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. 
*/
static bool
put_user (uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       :"=&a" (error_code), "=m" (*udst)
       : "q" (byte));
  return error_code != -1;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  /* add */

  list_init (&file_list);
  lock_init (&file_lock);
  /*eadd */
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t *sp = f->esp; //suppose all arguments are 4 bytes
 // printf("%x\n",sp+2);
 // printf("%d %d\n",*(sp + 1),*(sp + 3));
  check_valid_ptr (sp + 0,sizeof(uint32_t));
  switch ((uint32_t)(*(sp+0))) {
  case SYS_HALT:
    sys_halt ();
    break;
    
  case SYS_EXIT:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    sys_exit ((uint32_t)(*(sp+1)));
    break;
    
  case SYS_EXEC:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_exec ((uint32_t)(*(sp+1)));
    break;

  case SYS_WAIT:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_wait ((uint32_t)(*(sp+1)));
    break;
    
  case SYS_CREATE:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    check_valid_ptr (sp + 2,sizeof(uint32_t));
    f->eax = sys_create ((uint32_t)(*(sp+1)), 
                         (uint32_t)(*(sp+2)));
    break;
    
  case SYS_REMOVE:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_remove ((uint32_t)(*(sp+1)));
    break;

  case SYS_OPEN:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_open ((uint32_t)(*(sp+1)));
    break;

  case SYS_FILESIZE:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_filesize ((uint32_t)(*(sp+1)));
    break;

  case SYS_READ:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    check_valid_ptr (sp + 2,sizeof(uint32_t));
    check_valid_ptr (sp + 3,sizeof(uint32_t));
    f->eax = sys_read ( (uint32_t)(*(sp+1)),
	                    (uint32_t)(*(sp+2)),
		            	(uint32_t)(*(sp+3)));
    break;

  case SYS_WRITE:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    check_valid_ptr (sp + 2,sizeof(uint32_t));
    check_valid_ptr (sp + 3,sizeof(uint32_t));
    f->eax = sys_write ( (uint32_t)(*(sp+1)),
			(uint32_t)(*(sp+2)),
			(uint32_t)(*(sp+3)));
    break;

  case SYS_SEEK:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    check_valid_ptr (sp + 2,sizeof(uint32_t));
    f->eax = sys_seek ((uint32_t)(*(sp+1)), 
                         (uint32_t)(*(sp+2)));
    break;

  case SYS_TELL:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_tell ((uint32_t)(*(sp+1)));
    break;

  case SYS_CLOSE:
    check_valid_ptr (sp + 1,sizeof(uint32_t));
    f->eax = sys_close ((uint32_t)(*(sp+1)));
    break;
  }
}


static int
sys_write (int fd, const void *buffer, unsigned length)
{
  check_valid_ptr (buffer, length);
  struct file * f;
  int ret;
  ret = -1;
  lock_acquire (&file_lock);	//写入文件时，获得一把锁，写的时候不允许其他进程读写
  if (fd == STDOUT_FILENO) { /* stdout */
    putbuf (buffer, length);
  } else if( fd == 0) {
  
  } else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length))
    {
      lock_release (&file_lock);
      sys_exit (-1);	//如果不在用户空间则错误
    }
  else
    {
      f = find_file_by_fd (fd);
      if (f != NULL) {	//得到要写的文件
		ret = file_write (f, buffer, length);	//写
	  }
	}
  lock_release (&file_lock);	//释放锁
  return ret;
}

int
sys_exit (int status)
{
  /* Close all the files */
  struct thread *t;
  struct list_elem *l;
  
  t = thread_current ();
  while (!list_empty (&t->files)) //获得当前的线程并关闭当前线程打开的文件
    {
      l = list_begin (&t->files);
      sys_close (list_entry (l, struct fd_elem, thread_elem)->fd);
    }
  
  t->ret_status = status;	
  thread_exit ();
  return -1;
}

static int
sys_halt (void)
{
  shutdown_power_off();
}

static int
sys_create (const char *file, unsigned initial_size)
{
  check_valid_ptr (file, 1); //ensure argument passing to strlen is valid
  check_valid_ptr (file+1, strlen (file));

  lock_acquire (&file_lock);
  bool success = filesys_create (file, initial_size);
//  if(success)
//	  printf("1\n");
//  else
//	  printf("0\n");
  
  lock_release (&file_lock);
  return success;
}

static int
sys_open (const char *file)
{
  check_valid_ptr (file, 1);
  check_valid_ptr (file+1, strlen (file));
  struct file *f;
  struct fd_elem *fde;
  int ret;
  
  ret = -1; 
  if (!file)
    return -1;
  if (!is_user_vaddr (file))
    sys_exit (-1);
  f = filesys_open (file);
  if (!f) 
    return -1;
  check_valid_ptr (file, 1);
  check_valid_ptr (file+1, strlen (file));
  fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
  if (!fde) 
    {
      file_close (f);
      return -1;
    }

  fde->file = f;
  fde->fd = alloc_fid ();
  list_push_back (&file_list, &fde->elem);
  list_push_back (&thread_current ()->files, &fde->thread_elem); //把打开的文件插入到当前线程的文件列表中
  ret = fde->fd;

  return ret;
}

static int
sys_close(int fd)
{
  struct fd_elem *f;
  int ret;

  f = find_fd_elem_by_fd_in_process(fd);
  
  if (!f)
	  return 0;

  file_close (f->file);
  list_remove (&f->elem);
  list_remove (&f->thread_elem);
  free (f);
  return 0;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  check_valid_ptr (buffer, size);
  struct file *f;
  int ret;
  lock_acquire (&file_lock);
  
  if (!is_user_vaddr (buffer) || !is_user_vaddr(buffer + size)) {
    lock_release (&file_lock);
	sys_exit (-1);
  } else if (fd == 0) {
	int i = 0;
    for (;i < size; i++) {
	  *(uint8_t *)(buffer + i) = input_getc ();
	}
	lock_release(&file_lock);
	return size;
  } else {
	  f = find_file_by_fd(fd);
	  if(f) {
	    ret = file_read (f, buffer, size);
	  }
      lock_release(&file_lock);
	  return ret;
  }
  return 0;
}

static int
sys_exec (const char *cmd)
{
  check_valid_ptr (cmd, 1);
  check_valid_ptr (cmd+1, strlen(cmd));
  int ret;
	  
//  if (!cmd || !is_user_vaddr (cmd)) /* 不在用户空间或错误指针则返回-1 */
//	 return -1;

//  ret = process_execute (cmd);

  lock_acquire (&file_lock);
  ret = process_execute (cmd);
  lock_release (&file_lock);
  return ret;
}

static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

static struct file *
find_file_by_fd (int fd)	//通过fd找到文件
{
  struct fd_elem *ret;
  
  ret = find_fd_elem_by_fd_in_process (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

static struct fd_elem *
find_fd_elem_by_fd (int fd)//在文件列表中找到文件节点
{
  struct fd_elem *ret;
  struct list_elem *l; 
  for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
    {
      ret = list_entry (l, struct fd_elem, elem); 
      if (ret->fd == fd)
       // printf("%d\n",ret->fd);
		return ret;
    }
 // printf("Not find\n");  
  return NULL;
}

static int
alloc_fid (void)
{
  static int fid = 2;
  return fid++;
}

static int
sys_filesize (int fd)
{
    struct file *f;
	  
	f = find_file_by_fd (fd);
	if (!f)
		return -1;
//	lock_acquire(&file_lock);
	int size = file_length (f);
//	lock_release(&file_lock);
	return size;
}

static int
sys_tell (int fd)
{
    struct file *f;
	  
	f = find_file_by_fd (fd);
	if (!f)
		return -1;
	return file_tell (f);
}

static int
sys_seek (int fd, unsigned pos)
{
    struct file *f;
	  
	f = find_file_by_fd (fd);
	if (!f)
		return -1;
	file_seek (f, pos);
	return 0; 
}

static int
sys_remove (const char *file)
{
 // check_valid_ptr (file, 1);
 // check_valid_ptr (file+1, strlen(file));
  if (!file)
	return false;
  
  if (!is_user_vaddr (file))
	sys_exit (-1);	      
  return filesys_remove (file);
}

static struct fd_elem *
find_fd_elem_by_fd_in_process (int fd)
{
  struct fd_elem *ret;
  struct list_elem *l;
  struct thread *t;
  
  t = thread_current ();
  
  for (l = list_begin (&t->files); l != list_end (&t->files); l = list_next (l))
    {
      ret = list_entry (l, struct fd_elem, thread_elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}

void 
check_valid_ptr (char *ptr, size_t size) {
  size_t i;
  for (i = 0; i < size; i++, ptr++) {
    if (!is_user_vaddr (ptr))
      sys_exit (-1);
    else if (ptr == NULL)
      sys_exit (-1);
    else if (get_user (ptr) == -1)
      sys_exit (-1);
    }
}
