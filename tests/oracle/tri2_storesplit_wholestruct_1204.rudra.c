/* ---- 0x49a0: progressbarinit (94 bytes) ---- */
void progressbarinit(ProgressData *bar)

{
  int iVar1;
  char *__nptr;
  long lVar2;
  
  bar->total = 0;
  bar->prev = 0;
  bar->point = 0;
  bar->width = 0;
  bar->field_0x1c = 0;
  curl_getenv("COLUMNS");
  if (__nptr != (char *)0x0) {
    lVar2 = strtol(__nptr,0,10);
    bar->width = (int)lVar2;
    free(__nptr);
    return;
  }
  bar->width = 'O';
  return;
}

/* ---- 0x3460: my_fwrite (98 bytes) ---- */
int my_fwrite(void *buffer,size_t size,size_t nmemb,FILE *stream)

{
  size_t sVar1;
  _IO_FILE *__s;
  
  __s = (_IO_FILE *)stream->_IO_read_ptr;
  __s = fopen(*(char * *)stream,"wb");
  stream->_IO_read_ptr = (char *)__s;
  if ((__s != (char *)0x0) && (__s == (_IO_FILE *)0x0)) {
    return -1;
  }
  sVar1 = fwrite(buffer,size,nmemb,__s);
  return (int)sVar1;
}
