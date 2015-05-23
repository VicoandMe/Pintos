#include <debug.h>
#include <stdint.h>

#define f (1<<14)

int int_to_fp(int);
int fp_to_int_zero(int);
int fp_to_int_nearest(int);
int add_fp_fp(int ,int );
int sub_fp_fp(int ,int );
int add_fp_int(int ,int );
int sub_fp_int(int ,int );
int multi_fp_fp(int ,int );
int multi_fp_int(int ,int );
int div_fp_fp(int ,int );
int div_fp_int(int ,int );
/////////////////////////////////////////////////////////////

int int_to_fp(int n) {
  return n*f;
}

int fp_to_int_zero(int x) {
  return x/f;
}

int fp_to_int_nearest(int x) {
 if(x >= 0)
	 return (x+f/2)/f;
 else
	 return (x-f/2)/f;
}

int add_fp_fp(int x, int y) {
  return x+y;
}

int sub_fp_fp(int x, int y) {
  return x-y;
}

int add_fp_int(int x,int n) {
	 return x+n*f;
}

int sub_fp_int(int x,int n) {
  return x-n*f;
}

int multi_fp_fp(int x,int y) {
  return  ((int64_t) x)*y/f;
}

int multi_fp_int(int x,int n) {
  return x*n;
}

int div_fp_fp(int x,int y) {
  return  ((int64_t) x)*f/y;
}
   
int div_fp_int(int x,int n) {
    return x/n;
 }
